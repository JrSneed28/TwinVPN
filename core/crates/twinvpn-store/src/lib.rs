//! `twinvpn-store` — the Tier-2 vault, its transaction engine, and the
//! anti-rollback machinery.
//!
//! **Authority:** [ADR-0020](../../../../docs/adr/ADR-0020-local-persistence-and-secure-storage.md)
//! in full; ADR-0018 CB-7 (where the store splits), CB-5 row 3 and CB-6a (the
//! SEK's custody); ADR-0009 R-9 and §11.4; ADR-0007 N-26.
//!
//! **Owner:** `core-security`.
//!
//! # CB-7, which is what this crate is
//!
//! > "A transaction engine is *all decision* — write-ahead ordering, crash
//! > recovery, monotone rejection, migration — so CB-1 and CB-2 put it in the
//! > core, and ten shells implementing it is R-31's defect class in its purest
//! > form."
//!
//! So this crate owns: record envelopes ([`record`]), the AEAD's *use* (the AEAD
//! itself is in `twinvpn-crypto` under CD-I2), namespaces ([`namespace`]),
//! schema and migration ([`migrate`]), monotone-floor rejection ([`floors`]),
//! the recovery ladder ([`Store::open`]), and multi-key commit
//! ([`Store::commit`]). Tier-2 file I/O is core-side beneath a shell-vended
//! `store_root` ([`vault`]).
//!
//! It does **not** own, and cannot reach: vending `store_root`, the file
//! protection class, backup exclusion, or the Tier-1 items themselves. Those are
//! the shell's, through [`twinvpn_platform::SecureStore`].
//!
//! # The three properties this crate exists to hold
//!
//! | Property | Where |
//! |---|---|
//! | **A floor never decreases.** N-26: "A lower value MUST be refused … **not applied**" | [`floors::FloorSet`] has no setter; the only mutation takes a [`floors::FloorProposal`], which only a comparison can produce |
//! | **A multi-key commit is atomic.** ST-12b: a `TrustedPeer` and a `trust_epoch` advance commit together or not at all | [`Store::commit`] builds one image and publishes it with one `rename(2)` |
//! | **A rolled-back vault is detected.** ST-24: the anchor's floors win | [`anchor::AnchorState::classify`] is the table, and [`Store::open`] acts on it |
//!
//! # What the ladder may never do
//!
//! ST-35: "No rung tears down an established `Session` (**I5**), no rung
//! disengages the kill switch (**I3**), and **no rung lowers a floor**. A rung
//! may only make the device *less* authorized." This crate holds no session and
//! no rule set, so the first two are true by construction; the third is
//! [`floors`]'s job and is asserted by its tests and by
//! `tests/recovery_ladder.rs`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod anchor;
pub mod error;
pub mod floors;
pub mod migrate;
pub mod namespace;
pub mod record;
pub mod vault;

#[cfg(any(test, feature = "test-support"))]
pub mod testenv;

use std::collections::BTreeMap;
use std::sync::Arc;

use twinvpn_crypto::aead::StoreKey;
use twinvpn_env::Env;
use twinvpn_platform::custody::{RecordAeadCustody, SecureItem, SecureItemKey, SecureStore};

pub use anchor::{Anchor, AnchorState};
pub use error::{Result, Rung, StoreError};
pub use floors::{FloorId, FloorProposal, FloorSet};
pub use namespace::{Namespace, RecordKey};
pub use record::Record;
pub use vault::{Vault, VaultPaths};

/// What [`Store::open`] concluded, so the composition root can act on it.
///
/// Returned rather than logged, because ST-24's outcomes drive behaviour outside
/// this crate: suspending granted authority is `twinvpn-trust`'s and
/// `twinvpn-enforce`'s, and re-pulling documents is `twinvpn-cp-client`'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOutcome {
    /// ST-24's classification.
    pub state: AnchorState,
    /// The rung the ladder entered at.
    pub rung: Rung,
    /// Whether granted authority — exit use, LAN access, route acceptance, new
    /// pairing — must be suspended until a fresh signed document at or above the
    /// floors verifies.
    ///
    /// **Never** a reason to refuse a handshake to a known peer or to tear down
    /// a session (ST-35, R-11, I5).
    pub suspend_granted_authority: bool,
    /// Whether the vault was rebuilt empty (rung L3).
    pub vault_rebuilt: bool,
    /// The floors in force after the ladder ran.
    pub floors: FloorSet,
    /// What the locked allocator granted for the SEK, for `CoreBuildIdentity`
    /// (S-46) and the diagnostic bundle (CB-6a).
    pub sek_custody: SekCustody,
}

/// CB-6a's declared per-target fact about the store key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SekCustody {
    /// Who performs the record AEAD on this target.
    pub aead: RecordAeadCustody,
    /// What the locked allocator actually achieved, where the key is core-held.
    ///
    /// `None` when the platform performs the AEAD and no key is core-held.
    pub locked: Option<twinvpn_crypto::LockedMemoryReport>,
}

impl SekCustody {
    /// A stable tag for `CoreBuildIdentity` and the diagnostic bundle.
    ///
    /// CB-6a: "so 'this device's vault key was software-held' is a readable fact
    /// rather than an inference."
    #[must_use]
    pub fn tag(&self) -> String {
        match (self.aead, self.locked) {
            (RecordAeadCustody::PlatformPerformed, _) => "platform-aead".to_owned(),
            (RecordAeadCustody::CoreHeld, Some(r)) => format!("core-held:{}", r.tag()),
            (RecordAeadCustody::CoreHeld, None) => "core-held:unreported".to_owned(),
        }
    }
}

/// One multi-key transaction (ST-12b).
///
/// Writes, deletes and floor advances that commit **together or not at all**.
/// ST-12b states the failure a per-key write produces: "if the `TrustedPeer`
/// record commits and the floor advance does not, the device admits a peer under
/// an epoch its floor does not reflect; reversed, it refuses a peer it should
/// accept."
#[derive(Debug, Default)]
pub struct Transaction {
    writes: Vec<(RecordKey, Record)>,
    deletes: Vec<RecordKey>,
    floors: Vec<(FloorId, u64)>,
}

impl Transaction {
    /// An empty transaction.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a record write.
    ///
    /// `verbatim_signed` marks ST-13's rule: the value is the **received
    /// octets** of a signed statement and must be stored unchanged. The store
    /// never decodes it, so the flag is a fact the reader needs rather than
    /// something this crate enforces on itself.
    #[must_use]
    pub fn write(
        mut self,
        key: RecordKey,
        value: Vec<u8>,
        verbatim_signed: bool,
        rec_seq: u64,
    ) -> Self {
        let record = Record::new(key.namespace(), rec_seq, verbatim_signed, value);
        self.writes.push((key, record));
        self
    }

    /// Adds a record deletion.
    #[must_use]
    pub fn delete(mut self, key: RecordKey) -> Self {
        self.deletes.push(key);
        self
    }

    /// Proposes a floor value. A decrease refuses the **whole** transaction.
    #[must_use]
    pub fn advance_floor(mut self, id: FloorId, value: u64) -> Self {
        self.floors.push((id, value));
        self
    }

    /// Whether this transaction changes anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty() && self.deletes.is_empty() && self.floors.is_empty()
    }
}

/// The open vault.
pub struct Store {
    env: Env,
    custody: Arc<dyn SecureStore>,
    paths: VaultPaths,
    sek: StoreKey,
    ns_keys: BTreeMap<Namespace, StoreKey>,
    vault: Vault,
    floors: FloorSet,
    outcome: OpenOutcome,
    commit_crash: Option<CommitCrash>,
}

/// Where an injected crash stops [`Store::commit`].
///
/// ADR-0020 §11.17 lists the P19 observables, and one of them is
/// "**Crash-injection point** | RQ-12 injected clock/step source | the ST-23
/// step number at which the process is killed". This is that point, as a closed
/// type rather than an integer, so a caller cannot name a boundary that does not
/// exist.
///
/// # Why exactly one boundary
///
/// ST-23's whole crash argument is the ORDER of steps 3 and 5 — "a crash between
/// them leaves `anchor.store_seq > vault.store_seq`, which ST-24 classifies as a
/// rollback" — so the window between them is the one that decides whether an
/// advanced floor survives. The other windows are already decided elsewhere and
/// a knob for them would carry no assertion: a crash between steps 5 and 6
/// leaves equal `store_seq`s with differing digests, which ST-24 row 3 makes
/// `STORE.ANCHOR_MISMATCH` (FATAL) by design, and a crash before step 3 has
/// written nothing at all.
///
/// The variant is deliberately named for the two WRITES rather than for a step
/// number. It marks the source position between them, so a build that reorders
/// them — which is `M-P19-3` — moves the window's meaning with the reorder
/// instead of silently injecting somewhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitCrash {
    /// Between the Tier-1 anchor write and the Tier-2 vault commit.
    ///
    /// In ST-23's order the anchor is already durable with the new floors and
    /// the vault is not, so ST-24 row 2 classifies the reopen as a rollback and
    /// **the anchor's floors win**. Reverse the two and the same window leaves
    /// the vault ahead of an anchor still holding the old floors, which ST-24
    /// row 4 resolves to `max(anchor, vault)` — and
    /// [`vault_floors`] is empty, so that maximum is the OLD floor set and the
    /// advance is lost.
    BetweenAnchorAndVault,
}

impl Store {
    /// Opens the store, running ST-24's classification and the §11.11 ladder.
    ///
    /// `identity_present` is the caller's report from
    /// `IdentityCustody::public_identity` — this crate never touches identity
    /// material (CB-5), so it is told rather than looking.
    ///
    /// # Errors
    ///
    /// [`StoreError::SchemaTooNew`] — refused, never repaired;
    /// [`StoreError::AnchorMismatch`] on a fork, which is fatal;
    /// [`StoreError::SecureStoreUnavailable`] if Tier 1 refuses;
    /// [`StoreError::VaultIo`] for a file-set failure.
    pub async fn open(
        env: Env,
        custody: Arc<dyn SecureStore>,
        identity_present: bool,
    ) -> Result<Self> {
        let root = custody.store_root().await?;
        let paths = VaultPaths::new(root.path.clone());
        // E3 / §11.9: single opener, refused rather than shared.
        vault::acquire_lock(&paths, "twinvpn-store")?;

        let sek_key = SecureItemKey::new(anchor::SEK_ITEM)?;
        let anchor_key = SecureItemKey::new(anchor::ANCHOR_ITEM)?;

        // Tier 1 first: the SEK and the anchor are what the ladder recovers
        // *from*, so a failure here is not something a vault rebuild can fix.
        let (sek, store_id_from_sek) = Self::load_or_create_sek(&env, &*custody, &sek_key).await?;
        let stored_anchor = match custody.secure_item_read(&anchor_key).await? {
            Some(item) => Some(Anchor::decode(item.as_bytes())?),
            None => None,
        };

        // Tier 2.
        let raw = vault::read_vault(&paths)?;
        let decoded = match &raw {
            Some(bytes) => match Vault::decode(bytes) {
                Ok(v) => Some(Ok(v)),
                // ST-15 rule 2: a future schema is refused and the file is left
                // alone. It does not enter the ladder.
                Err(e @ StoreError::SchemaTooNew { .. }) => {
                    vault::release_lock(&paths)?;
                    return Err(e);
                }
                Err(e) => Some(Err(e)),
            },
            None => None,
        };

        let vault_summary = match &decoded {
            Some(Ok(v)) => Some((v.store_seq, v.digest())),
            // An unreadable vault is not a *rolled back* vault; it is rung L3.
            // Reporting it as `None` here would classify it as ST-24 row 7's
            // benign reinstall path, which is exactly the wrong direction.
            Some(Err(_)) => Some((0, [0u8; 32])),
            None => None,
        };

        let state = AnchorState::classify(stored_anchor.as_ref(), vault_summary, identity_present);

        // A fork is fatal and is not recovered from here: ST-24 row 3 quarantines
        // the vault and performs an identity-only bootstrap, which is a decision
        // for the composition root because it re-enters `RECONNECTING` per peer.
        if let AnchorState::Forked { store_seq } = state {
            vault::release_lock(&paths)?;
            return Err(StoreError::AnchorMismatch { store_seq });
        }

        let store_id = stored_anchor
            .as_ref()
            .map_or(store_id_from_sek, |a| a.store_id);

        let anchor_floors = stored_anchor
            .as_ref()
            .map_or_else(FloorSet::new, |a| a.floors.clone());

        // Rung selection.
        let (mut vault_image, rung, vault_rebuilt) = match decoded {
            Some(Ok(v)) => (v, Rung::L0, false),
            Some(Err(_)) => {
                // L3: quarantine, rebuild empty, seed floors from Tier 1 —
                // "never from the quarantined file".
                let tag = format!("{:016x}", store_seq_tag(stored_anchor.as_ref()));
                vault::quarantine_vault(&paths, &tag)?;
                (Vault::empty(store_id), Rung::L3, true)
            }
            None => (Vault::empty(store_id), Rung::L0, false),
        };
        vault_image.store_id = store_id;

        // ST-24's floor resolution.
        //
        // Rows 1, 2, 5, 6 and 7 all take the anchor's floors: it is the only
        // source the ladder trusts, and where it is absent the floors are
        // unverified and granted authority is suspended. Row 4 —
        // `AnchorState::AnchorBehind` — says `max(anchor, vault)`, and reduces
        // to the same value here because the vault-side floor mirror is not yet
        // written (see `vault_floors`). The `merge_max` is applied anyway rather
        // than being dropped, so that the arithmetic is already correct when the
        // mirror lands: taking the *minimum* would silently lower a floor, which
        // is the rollback the anchor exists to prevent.
        let floors = anchor_floors.merge_max(&vault_floors(&vault_image));

        let rung = match &state {
            AnchorState::VaultRolledBack { .. } => Rung::L5,
            AnchorState::AnchorMissingIdentityPresent => Rung::L4,
            _ => rung,
        };

        let outcome = OpenOutcome {
            state: state.clone(),
            rung,
            suspend_granted_authority: state.suspends_granted_authority(),
            vault_rebuilt,
            floors: floors.clone(),
            sek_custody: SekCustody {
                aead: custody.record_aead_custody(),
                locked: Some(sek.custody_report()),
            },
        };

        // ADR-0015: the one event this crate emits. The ladder's classification
        // is an operational fact a support engineer needs and cannot reconstruct
        // — "was this device's vault rolled back" has no other witness — and
        // every field here is `OPERATIONAL`: a rung, a boolean, a custody tag
        // and a count. No key, no record, no `device_id`, and no path.
        //
        // Nothing else in this crate logs. A record's contents are secret by
        // namespace, a floor's per-peer name carries a `device_id`, and the
        // remaining outcomes are returned as typed values for the composition
        // root to render through `twinvpn-diag`, which owns presentation (CB-4).
        tracing::info!(
            target: "twinvpn::store",
            rung = outcome.rung.tag(),
            suspend_granted_authority = outcome.suspend_granted_authority,
            vault_rebuilt = outcome.vault_rebuilt,
            sek_custody = %outcome.sek_custody.tag(),
            floors_held = outcome.floors.pairs().count(),
            "vault opened"
        );

        let mut store = Self {
            env,
            custody,
            paths,
            sek,
            ns_keys: BTreeMap::new(),
            vault: vault_image,
            floors,
            outcome,
            commit_crash: None,
        };
        store.derive_namespace_keys(store_id)?;
        Ok(store)
    }

    /// Arms the ST-23 crash-injection point (ADR-0020 §11.17's P19 observable).
    ///
    /// The next [`Self::commit`] stops at `at` with
    /// [`StoreError::CommitCrashInjected`], having performed every earlier step
    /// and no later one, and without publishing the new vault or floors into
    /// this handle. Reopening from the same custody then sees exactly the
    /// on-disk state a kill at that boundary would have left.
    ///
    /// Behind `test-support`, which is never enabled in a shipped build: the
    /// field it sets exists unconditionally so `commit` reads one `Option` on
    /// every path rather than compiling to two different functions, but nothing
    /// in a shipped build can set it to anything but `None`.
    #[cfg(feature = "test-support")]
    pub const fn inject_commit_crash(&mut self, at: Option<CommitCrash>) {
        self.commit_crash = at;
    }

    /// Whether an injected crash fires at `at`.
    fn crashes_at(&self, at: CommitCrash) -> Result<()> {
        if self.commit_crash == Some(at) {
            return Err(StoreError::CommitCrashInjected { at });
        }
        Ok(())
    }

    /// What the open concluded.
    #[must_use]
    pub const fn outcome(&self) -> &OpenOutcome {
        &self.outcome
    }

    /// The floors currently in force.
    #[must_use]
    pub const fn floors(&self) -> &FloorSet {
        &self.floors
    }

    /// The vault's commit counter.
    #[must_use]
    pub const fn store_seq(&self) -> u64 {
        self.vault.store_seq
    }

    /// Reads and decrypts a record.
    ///
    /// # Errors
    ///
    /// [`StoreError::RecordCorrupt`] if the envelope fails its tag — rung L1.
    /// `Ok(None)` for an absent record, which is a normal state and never an
    /// error.
    pub fn get(&self, key: &RecordKey) -> Result<Option<Record>> {
        let Some(envelope) = self.vault.records.get(&key.flat()) else {
            return Ok(None);
        };
        let k = self.namespace_key(key.namespace())?;
        record::open_record(k, &self.vault.store_id, key, envelope).map(Some)
    }

    /// Every key in one namespace.
    ///
    /// Namespace-scoped by construction (ST-14a): there is no glob, no prefix
    /// argument, and no "all keys" form.
    #[must_use]
    pub fn keys_in(&self, namespace: Namespace) -> Vec<RecordKey> {
        self.vault
            .records
            .keys()
            .filter_map(|k| RecordKey::parse(k).ok())
            .filter(|k| k.namespace() == namespace)
            .collect()
    }

    /// Commits a multi-key transaction in ST-23's order.
    ///
    /// ```text
    /// 1. verify the document                       (the caller's, before this)
    /// 2. compute new floor set; a decrease -> REFUSE
    /// 3. write ANCH with the new floors and store_seq + 1        [Tier 1]
    /// 4. hardware counter, where one exists and a trust floor advanced
    /// 5. commit the vault transaction                            [Tier 2]
    /// 6. write ANCH again with the new vault_digest              [Tier 1]
    /// ```
    ///
    /// Steps 3 and 5 are deliberately in that order: a crash between them leaves
    /// `anchor.store_seq > vault.store_seq`, which ST-24 classifies as a
    /// rollback. "**Erring toward 'rollback' on an ambiguous crash is the
    /// correct direction**, because the cost is a re-pull and the alternative
    /// cost is a resurrected revocation."
    ///
    /// Step 4 is a no-op here: no hardware counter is reachable through
    /// [`SecureStore`], which offers whole-blob items and no monotonic counter.
    /// [`FloorProposal::advances_a_trust_floor`] carries the signal so a shell
    /// that gains one can act on it, and the absence is reported.
    ///
    /// # Errors
    ///
    /// [`StoreError::FloorWouldDecrease`] at step 2 — and then **nothing is
    /// written**; [`StoreError::SecureStoreUnavailable`] at 3 or 6;
    /// [`StoreError::VaultIo`] at 5.
    pub async fn commit(&mut self, tx: Transaction) -> Result<FloorProposal> {
        // Step 2, before anything is written anywhere.
        let proposal = self.floors.propose(&tx.floors)?;

        let next_seq = self.vault.store_seq + 1;
        let mut new_floors = self.floors.clone();
        new_floors.apply(&proposal);

        // Build the candidate image before touching Tier 1, so a failure to
        // encode does not leave an advanced anchor over an unchanged vault.
        let mut candidate = self.vault.clone();
        candidate.store_seq = next_seq;
        for key in &tx.deletes {
            candidate.records.remove(&key.flat());
        }
        for (key, rec) in &tx.writes {
            let k = self.namespace_key(key.namespace())?;
            let envelope = record::seal_record(&self.env, k, &candidate.store_id, key, rec)?;
            candidate.records.insert(key.flat(), envelope);
        }
        let image = candidate.encode();

        let anchor_key = SecureItemKey::new(anchor::ANCHOR_ITEM)?;

        // Step 3: the anchor advances FIRST, with the new floors, and with a
        // deliberately wrong `vault_digest` — the vault has not been written
        // yet, and claiming a digest for content that does not exist would make
        // a crash here look healthy.
        let pre = Anchor::new(candidate.store_id, next_seq, [0u8; 32], &new_floors);
        self.write_anchor(&anchor_key, &pre).await?;

        // Step 4: no hardware counter is available through this seam.
        let _ = proposal.advances_a_trust_floor();

        // The ST-23 crash-injection point (ADR-0020 §11.17), between the two
        // writes whose ORDER is the rule's entire argument. It sits here rather
        // than beside either write so that a build reordering them moves this
        // window with them.
        self.crashes_at(CommitCrash::BetweenAnchorAndVault)?;

        // Step 5.
        vault::commit_vault(&self.paths, &image)?;

        // Step 6.
        let post = Anchor::new(
            candidate.store_id,
            next_seq,
            candidate.digest(),
            &new_floors,
        );
        self.write_anchor(&anchor_key, &post).await?;

        self.vault = candidate;
        self.floors = new_floors;
        Ok(proposal)
    }

    /// Releases the single-opener lock. Idempotent.
    ///
    /// `ownership.md` §6 rule 7: graceful shutdown. A store that exits without
    /// releasing its lock makes the next start report `STORE.LOCK_CONTENDED`
    /// against a process that is gone.
    ///
    /// # Errors
    ///
    /// [`StoreError::VaultIo`].
    pub fn close(&self) -> Result<()> {
        vault::release_lock(&self.paths)
    }

    fn namespace_key(&self, ns: Namespace) -> Result<&StoreKey> {
        self.ns_keys.get(&ns).ok_or(StoreError::CryptoInvariant {
            invariant: "every declared namespace has a derived key",
        })
    }

    fn derive_namespace_keys(&mut self, store_id: [u8; 16]) -> Result<()> {
        for ns in namespace::ALL {
            let k = self.sek.derive_namespace_key(&store_id, ns.as_str())?;
            self.ns_keys.insert(*ns, k);
        }
        Ok(())
    }

    async fn write_anchor(&self, key: &SecureItemKey, a: &Anchor) -> Result<()> {
        let bytes = a.encode()?;
        let item = SecureItem::new(bytes);
        self.custody.secure_item_write_atomic(key, &item).await?;
        Ok(())
    }

    async fn load_or_create_sek(
        env: &Env,
        custody: &dyn SecureStore,
        key: &SecureItemKey,
    ) -> Result<(StoreKey, [u8; 16])> {
        if let Some(item) = custody.secure_item_read(key).await? {
            // The Tier-1 item is `SEK || store_id`, so a vault and its key are
            // never separated: a restored Tier 1 brings its own `store_id`, and
            // an SEK that arrived without one would let a caller pick the salt.
            let mut raw = item.into_bytes();
            if raw.len() != 48 {
                return Err(StoreError::CustodyDegraded {
                    asset: "vault",
                    class_to: "malformed store key item",
                });
            }
            let mut store_id = [0u8; 16];
            store_id.copy_from_slice(&raw[32..48]);
            let sek = StoreKey::adopt_sek(&mut raw[..32])?;
            // `adopt_sek` erased its half; erase the rest of the buffer too.
            raw.fill(0);
            return Ok((sek, store_id));
        }

        // First run: mint an SEK and a `store_id` from the platform CSPRNG.
        // Never from a seeded stream — this key protects data at rest, and a
        // reproducible one would be no key at all.
        let mut fresh = [0u8; 48];
        env.entropy()
            .fill(&mut fresh)
            .map_err(|_| StoreError::CustodyDegraded {
                asset: "vault",
                class_to: "no platform entropy for a store key",
            })?;
        let mut store_id = [0u8; 16];
        store_id.copy_from_slice(&fresh[32..48]);
        custody
            .secure_item_write_atomic(key, &SecureItem::new(fresh.to_vec()))
            .await?;
        let sek = StoreKey::adopt_sek(&mut fresh[..32])?;
        fresh.fill(0);
        Ok((sek, store_id))
    }
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("store_seq", &self.vault.store_seq)
            .field("records", &self.vault.records.len())
            .field("rung", &self.outcome.rung)
            .finish_non_exhaustive()
    }
}

/// The floors a vault image itself claims, for ST-24 row 4's `max`.
///
/// Held in `store/` as a record; a vault with no such record claims nothing,
/// which reads as every floor at zero and therefore never raises the anchor's.
fn vault_floors(_v: &Vault) -> FloorSet {
    // The vault-side mirror of the floor set is written by the caller into
    // `store/floors`, encrypted like any record. Reading it here would require a
    // namespace key that is derived after this point in `open`, so ST-24 row 4's
    // `max` is computed against an empty set — which is the conservative
    // direction: it can only leave the anchor's floors in force, never lower
    // them. Stated rather than silently approximated.
    FloorSet::new()
}

fn store_seq_tag(anchor: Option<&Anchor>) -> u64 {
    anchor.map_or(0, |a| a.store_seq)
}
