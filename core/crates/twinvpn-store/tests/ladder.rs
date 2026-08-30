//! The anti-rollback and recovery-ladder attack tests.
//!
//! **Authority:** ADR-0020 ST-23, ST-24, ST-35, §11.11, §15 (proof test P19 — "a
//! restored store cannot resurrect a revoked peer").
//!
//! Every test here names the attack it refutes, and each one **interrupts the
//! commit at a specific step** rather than asserting a happy path. A recovery
//! ladder whose rungs have never been entered is not a ladder.

use std::sync::Arc;

use twinvpn_platform::custody::{SecureItem, SecureItemKey, SecureStore};
use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_store::testenv::test_env;
use twinvpn_store::{
    anchor, Anchor, AnchorState, FloorId, Namespace, RecordKey, Rung, Store, StoreError,
    Transaction, Vault, VaultPaths,
};

/// A test fixture: a temp directory, a mock Tier-1 store, and an `Env`.
struct Fixture {
    dir: std::path::PathBuf,
    adapter: Arc<MockAdapter>,
    env: twinvpn_env::Env,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("twinvpn-store-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
        adapter.store_mock().set_store_root(dir.clone());
        Self {
            dir,
            adapter,
            env: test_env(),
        }
    }

    fn custody(&self) -> Arc<dyn SecureStore> {
        // The mock adapter's store is reached through the adapter, which owns
        // it; cloning the `Arc` keeps the adapter alive for the store's life.
        struct Bridge(Arc<MockAdapter>);
        impl SecureStore for Bridge {
            fn secure_item_read<'a>(
                &'a self,
                key: &'a SecureItemKey,
            ) -> futures_core::future::BoxFuture<
                'a,
                Result<Option<SecureItem>, twinvpn_platform::PlatformError>,
            > {
                self.0.store_mock().secure_item_read(key)
            }
            fn secure_item_write_atomic<'a>(
                &'a self,
                key: &'a SecureItemKey,
                value: &'a SecureItem,
            ) -> futures_core::future::BoxFuture<'a, Result<(), twinvpn_platform::PlatformError>>
            {
                self.0.store_mock().secure_item_write_atomic(key, value)
            }
            fn secure_item_delete<'a>(
                &'a self,
                key: &'a SecureItemKey,
            ) -> futures_core::future::BoxFuture<'a, Result<(), twinvpn_platform::PlatformError>>
            {
                self.0.store_mock().secure_item_delete(key)
            }
            fn store_root(
                &self,
            ) -> futures_core::future::BoxFuture<
                '_,
                Result<twinvpn_platform::custody::StoreRoot, twinvpn_platform::PlatformError>,
            > {
                self.0.store_mock().store_root()
            }
            fn record_aead_custody(&self) -> twinvpn_platform::custody::RecordAeadCustody {
                self.0.store_mock().record_aead_custody()
            }
        }
        Arc::new(Bridge(Arc::clone(&self.adapter)))
    }

    fn paths(&self) -> VaultPaths {
        VaultPaths::new(self.dir.clone())
    }

    fn open(&self, identity_present: bool) -> twinvpn_store::Result<Store> {
        drive(Store::open(
            self.env.clone(),
            self.custody(),
            identity_present,
        ))
    }

    /// Reads the Tier-1 anchor as the shell holds it.
    fn read_anchor(&self) -> Option<Anchor> {
        let key = SecureItemKey::new(anchor::ANCHOR_ITEM).expect("key");
        drive(self.adapter.store_mock().secure_item_read(&key))
            .expect("read")
            .map(|i| Anchor::decode(i.as_bytes()).expect("decode"))
    }

    /// Overwrites the Tier-1 anchor, as an attacker with Tier-1 write access
    /// would.
    fn write_anchor(&self, a: &Anchor) {
        let key = SecureItemKey::new(anchor::ANCHOR_ITEM).expect("key");
        let item = SecureItem::new(a.encode().expect("encode"));
        drive(
            self.adapter
                .store_mock()
                .secure_item_write_atomic(&key, &item),
        )
        .expect("write");
    }

    fn delete_anchor(&self) {
        let key = SecureItemKey::new(anchor::ANCHOR_ITEM).expect("key");
        drive(self.adapter.store_mock().secure_item_delete(&key)).expect("delete");
    }
}

/// Drives a future that completes without ever pending.
///
/// Every await point reached in these tests is either a `MockStore` call — an
/// in-memory `HashMap` — or synchronous file I/O, so the future is `Ready` on
/// its first poll and a no-op waker is sufficient. That is far clearer in a test
/// than threading a runtime through a fixture, and a future that *did* pend
/// would panic loudly rather than hang.
fn drive<T>(fut: impl core::future::Future<Output = T>) -> T {
    use core::task::{Context, Poll, Waker};
    let mut fut = Box::pin(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("a mock-backed future must be ready on first poll"),
    }
}

fn peer_key() -> RecordKey {
    RecordKey::new(Namespace::Peer, "alice").expect("key")
}

// ---------------------------------------------------------------------------
// The happy path, so the attack tests below are known to be testing something
// ---------------------------------------------------------------------------

#[test]
fn a_first_open_creates_a_vault_and_a_multi_key_commit_round_trips() {
    let f = Fixture::new("first-open");
    let mut store = f.open(true).expect("open");
    assert_eq!(store.outcome().rung, Rung::L0);
    assert!(!store.outcome().suspend_granted_authority);

    let tx = Transaction::new()
        .write(peer_key(), b"trusted-peer-record".to_vec(), true, 1)
        .advance_floor(FloorId::TrustEpoch, 5);
    let advanced = drive(store.commit(tx)).expect("commit");
    assert!(advanced.advances_a_trust_floor());

    let rec = store.get(&peer_key()).expect("get").expect("present");
    assert_eq!(rec.value, b"trusted-peer-record");
    assert!(
        rec.is_verbatim_signed(),
        "ST-13's flag must survive a round trip"
    );
    assert_eq!(store.floors().get(&FloorId::TrustEpoch), 5);
    assert_eq!(store.store_seq(), 1);
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// ATTACK: restore an older vault file
// ---------------------------------------------------------------------------

/// **Proof test P19 — "a restored store cannot resurrect a revoked peer".**
///
/// The attacker copies the vault file aside at `trust_epoch = 5`, lets the
/// device advance to 9, then restores the old file. ST-24 row 2 classifies the
/// result as a rollback, the **anchor's** floors win, and granted authority is
/// suspended until a fresh document at or above the floor verifies.
#[test]
fn a_restored_older_vault_cannot_lower_the_trust_epoch() {
    let f = Fixture::new("p19");
    let mut store = f.open(true).expect("open");
    let tx = Transaction::new()
        .write(peer_key(), b"peer@5".to_vec(), true, 1)
        .advance_floor(FloorId::TrustEpoch, 5);
    drive(store.commit(tx)).expect("commit");
    store.close().expect("close");

    // The attacker's copy, taken at epoch 5.
    let snapshot = std::fs::read(f.paths().vault()).expect("read vault");

    // The device advances to 9.
    let mut store = f.open(true).expect("reopen");
    let tx = Transaction::new()
        .write(peer_key(), b"peer@9".to_vec(), true, 2)
        .advance_floor(FloorId::TrustEpoch, 9);
    drive(store.commit(tx)).expect("commit");
    assert_eq!(store.floors().get(&FloorId::TrustEpoch), 9);
    store.close().expect("close");

    // The attack: put the old vault back. Tier 1 is untouched, which is the
    // realistic case — a file-level backup restore.
    std::fs::write(f.paths().vault(), &snapshot).expect("restore");

    let store = f.open(true).expect("open after restore");
    match store.outcome().state {
        AnchorState::VaultRolledBack { .. } => {}
        ref other => panic!("expected a rollback classification, got {other:?}"),
    }
    assert_eq!(store.outcome().rung, Rung::L5);
    assert!(
        store.outcome().suspend_granted_authority,
        "granted authority must be suspended after a rollback"
    );
    assert_eq!(
        store.floors().get(&FloorId::TrustEpoch),
        9,
        "the anchor's floor must win; a restored vault must not resurrect epoch 5"
    );
    store.close().expect("close");
}

/// Every file in `store_root`, as bytes. ADR-0020 §15 step 1 takes "a
/// **byte-level** snapshot of A's `store_root` — every file in §11.5's file
/// set", not one named file.
fn snapshot_store_root(dir: &std::path::Path) -> Vec<(std::ffi::OsString, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read store_root").flatten() {
        if entry.path().is_file() {
            let bytes = std::fs::read(entry.path()).expect("read file");
            out.push((entry.file_name(), bytes));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Puts `snapshot` back verbatim, removing anything that was not in it.
fn restore_store_root(dir: &std::path::Path, snapshot: &[(std::ffi::OsString, Vec<u8>)]) {
    std::fs::remove_dir_all(dir).expect("clear store_root");
    std::fs::create_dir_all(dir).expect("recreate store_root");
    for (name, bytes) in snapshot {
        std::fs::write(dir.join(name), bytes).expect("restore file");
    }
}

/// **Proof test P19, variant 2 — ST-22 co-location, driven rather than assumed.**
///
/// ADR-0020 §15 step 3: "Stop A's daemon. Restore `store_root` verbatim from the
/// `t0` snapshot. **Do not touch Tier 1.**" That instruction only means anything
/// if the anchor is *not in* `store_root`: ST-22 co-locates it with the identity
/// key in Tier 1, reached through `twinvpn_platform::SecureStore`, and
/// `anchor.rs` says so — "Co-location is the shell's to provide — the core
/// reaches Tier 1 only through `twinvpn_platform::SecureStore`".
///
/// So this restores the WHOLE store root, which is what a file-level backup
/// actually does, and asserts the floor still stands at `e1`. `M-P19-4` puts the
/// anchor in a plain file beside the vault; the same restore then carries the
/// old anchor back with it and the device comes up at `e0`.
///
/// `a_restored_older_vault_cannot_lower_the_trust_epoch` cannot see that: it
/// restores `vault.tv` alone, so an anchor moved to a sibling file survives its
/// restore untouched and the test stays green against the defect.
#[test]
fn a_restored_store_root_cannot_lower_a_floor_because_the_anchor_is_not_in_it() {
    let f = Fixture::new("p19-anchor-colocation");

    // t0, at e0.
    let mut store = f.open(true).expect("open");
    drive(
        store.commit(
            Transaction::new()
                .write(peer_key(), b"peer@e0".to_vec(), true, 1)
                .advance_floor(FloorId::TrustEpoch, 5),
        ),
    )
    .expect("commit e0");
    store.close().expect("close");

    let snapshot = snapshot_store_root(&f.dir);
    assert!(
        !snapshot.is_empty(),
        "the snapshot is empty, so the restore below would assert nothing"
    );

    // The device advances to e1.
    let mut store = f.open(true).expect("reopen");
    drive(
        store.commit(
            Transaction::new()
                .write(peer_key(), b"peer@e1".to_vec(), true, 2)
                .advance_floor(FloorId::TrustEpoch, 9),
        ),
    )
    .expect("commit e1");
    assert_eq!(store.floors().get(&FloorId::TrustEpoch), 9);
    store.close().expect("close");

    // §15 step 3. Tier 1 is the mock's in-memory item map and is NOT touched.
    restore_store_root(&f.dir, &snapshot);

    let store = f.open(true).expect("open after the store_root restore");
    assert_eq!(
        store.floors().get(&FloorId::TrustEpoch),
        9,
        "ADR-0020 §15 variant 2: restoring store_root must not lower the floor. \
         It can only fail to if the anchor lives OUTSIDE store_root, in Tier 1, \
         which is what ST-22's co-location buys."
    );
    match store.outcome().state {
        AnchorState::VaultRolledBack { .. } => {}
        ref other => panic!("expected a rollback classification, got {other:?}"),
    }
    assert!(store.outcome().suspend_granted_authority);
    store.close().expect("close");
}

/// **Proof test P19, oracle (b), through the ST-23 crash-injection point.**
///
/// ADR-0020 §15 oracle (b): "A's `effective_floor_set` after open shows
/// `trust_epoch = e1`, **not** `e0`." ADR-0020 §11.17 lists the injection point
/// itself as a P19 observable — "the ST-23 step number at which the process is
/// killed" — and this is that observable, driven.
///
/// The commit is killed in the window **between the anchor write and the vault
/// commit**. Under ST-23's order the anchor advanced first, so the new floor is
/// already durable in Tier 1 when the process dies: ST-24 row 2 sees
/// `anchor.store_seq > vault.store_seq`, classifies a rollback, and the
/// anchor's floors win. Reverse steps 3 and 5 — which is exactly `M-P19-3` —
/// and the same window leaves the vault ahead of an anchor still holding `e0`;
/// ST-24 row 4 resolves that to `max(anchor, vault)`, and the vault-side floor
/// mirror is empty, so the maximum is the OLD floor set and the advance is lost.
///
/// This is the assertion `a_restored_older_vault_cannot_lower_the_trust_epoch`
/// cannot make: that test never interrupts a commit, so the ORDER of steps 3
/// and 5 is invisible to it and a reordered build passes it unchanged.
#[test]
fn a_crash_between_the_anchor_and_the_vault_cannot_lose_the_advanced_floor() {
    let f = Fixture::new("p19-crash-st23");

    // e0 — the floor the attacker wants to come back to.
    let mut store = f.open(true).expect("open");
    let tx = Transaction::new()
        .write(peer_key(), b"peer@e0".to_vec(), true, 1)
        .advance_floor(FloorId::TrustEpoch, 5);
    drive(store.commit(tx)).expect("commit e0");
    store.close().expect("close");

    // e1 — advanced by a commit that is killed at the ST-23 boundary.
    let mut store = f.open(true).expect("reopen");
    store.inject_commit_crash(Some(twinvpn_store::CommitCrash::BetweenAnchorAndVault));
    let tx = Transaction::new()
        .write(peer_key(), b"peer@e1".to_vec(), true, 2)
        .advance_floor(FloorId::TrustEpoch, 9);
    match drive(store.commit(tx)) {
        Err(StoreError::CommitCrashInjected { .. }) => {}
        other => panic!("the injected crash did not fire: {other:?}"),
    }
    // Release the single-opener lock and drop the handle. `close` writes
    // nothing — it only releases the lock — so the ST-23 state left on disk is
    // exactly what the kill left. It stands in for the lock being reaped after
    // the process died, which is not what this test is about; whether a STALE
    // lock is recovered is `STORE.LOCK_CONTENDED`'s own question.
    store.close().expect("release the lock");
    drop(store);

    // The reopen is the oracle.
    let store = f.open(true).expect("open after the injected crash");
    assert_eq!(
        store.floors().get(&FloorId::TrustEpoch),
        9,
        "ADR-0020 §15 oracle (b): the floor set after open must show e1, not e0. \
         A crash between ST-23's steps must never lose an advanced floor — which \
         is only true while the anchor is written BEFORE the vault."
    );
    store.close().expect("close");
}

/// **Attack test — ST-23 step 2.** A commit that would lower a floor is refused,
/// and **nothing** is written: not the anchor, not the vault. A partial write
/// here would be the split state ST-12b exists to prevent.
#[test]
fn a_commit_that_would_lower_a_floor_writes_nothing() {
    let f = Fixture::new("floor-refusal");
    let mut store = f.open(true).expect("open");
    drive(
        store.commit(
            Transaction::new()
                .write(peer_key(), b"v1".to_vec(), false, 1)
                .advance_floor(FloorId::TrustEpoch, 7),
        ),
    )
    .expect("first commit");
    let seq_before = store.store_seq();
    let anchor_before = f.read_anchor().expect("anchor");

    let err = drive(
        store.commit(
            Transaction::new()
                .write(peer_key(), b"v2".to_vec(), false, 2)
                .advance_floor(FloorId::TrustEpoch, 3),
        ),
    )
    .expect_err("must refuse");
    assert!(matches!(
        err,
        StoreError::FloorWouldDecrease {
            floor: "trust_epoch",
            offered: 3,
            held: 7
        }
    ));
    assert_eq!(err.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");

    assert_eq!(
        store.store_seq(),
        seq_before,
        "the vault must not have moved"
    );
    let anchor_after = f.read_anchor().expect("anchor");
    assert_eq!(
        anchor_after.store_seq, anchor_before.store_seq,
        "the anchor must not have advanced"
    );
    assert_eq!(
        store.get(&peer_key()).expect("get").expect("present").value,
        b"v1",
        "the refused write must not have landed"
    );
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// ATTACK: interrupt the commit at each ST-23 step
// ---------------------------------------------------------------------------

/// **Crash test — ST-23 between steps 3 and 5.** The anchor advanced, the vault
/// did not. ADR-0020: "A crash between 3 and 5 leaves
/// `anchor.store_seq > vault.store_seq`, which is **indistinguishable from a
/// rollback and is treated as one**."
#[test]
fn a_crash_between_the_anchor_write_and_the_vault_commit_is_treated_as_a_rollback() {
    let f = Fixture::new("crash-3-5");
    let mut store = f.open(true).expect("open");
    drive(
        store.commit(
            Transaction::new()
                .write(peer_key(), b"v1".to_vec(), false, 1)
                .advance_floor(FloorId::TrustEpoch, 4),
        ),
    )
    .expect("commit");
    store.close().expect("close");

    // Simulate the crash: the anchor is at store_seq + 1 with advanced floors,
    // the vault is still at store_seq. This is exactly what step 3 leaves.
    let a = f.read_anchor().expect("anchor");
    let interrupted = Anchor::new(
        a.store_id,
        a.store_seq + 1,
        [0u8; 32],
        &twinvpn_store::FloorSet::from_pairs([(FloorId::TrustEpoch, 6)]),
    );
    f.write_anchor(&interrupted);

    let store = f.open(true).expect("open");
    match store.outcome().state {
        AnchorState::VaultRolledBack {
            crash_recovery: true,
            ..
        } => {}
        ref other => panic!("expected a crash-flagged rollback, got {other:?}"),
    }
    assert!(store.outcome().suspend_granted_authority);
    assert_eq!(
        store.floors().get(&FloorId::TrustEpoch),
        6,
        "the anchor's floors win, which is the safe direction"
    );
    store.close().expect("close");
}

/// **Crash test — ST-23 between steps 5 and 6.** The vault committed and the
/// second anchor write did not, so the anchor carries the pre-commit
/// `vault_digest`. ST-24 row 3 classifies equal sequence with differing digests
/// as a fork, which is fatal — and that is the correct, conservative outcome for
/// a state that is also what a tamper produces.
#[test]
fn a_crash_between_the_vault_commit_and_the_second_anchor_write_is_fatal() {
    let f = Fixture::new("crash-5-6");
    let mut store = f.open(true).expect("open");
    drive(store.commit(Transaction::new().write(peer_key(), b"v1".to_vec(), false, 1)))
        .expect("commit");
    store.close().expect("close");

    let a = f.read_anchor().expect("anchor");
    // Step 3's anchor: right sequence, placeholder digest.
    let interrupted = Anchor::new(a.store_id, a.store_seq, [0u8; 32], &a.floors);
    f.write_anchor(&interrupted);

    let err = f.open(true).expect_err("a fork must be fatal");
    assert!(matches!(err, StoreError::AnchorMismatch { .. }));
    assert_eq!(err.reason_code().as_str(), "STORE.ANCHOR_MISMATCH");
    // The vault file is left in place: it is the evidence, and ST-15 rule 2's
    // "MUST NOT delete, reset, downgrade, or repair" applies to every refusal.
    assert!(f.paths().vault().exists());
}

// ---------------------------------------------------------------------------
// ATTACK: strip the anchor
// ---------------------------------------------------------------------------

/// **Attack test — ST-22's payoff, part one.** Deleting the anchor while the
/// identity survives must suspend granted authority rather than silently
/// proceeding with unverified floors.
#[test]
fn deleting_the_anchor_with_the_identity_intact_suspends_granted_authority() {
    let f = Fixture::new("anchor-stripped");
    let mut store = f.open(true).expect("open");
    drive(store.commit(Transaction::new().advance_floor(FloorId::TrustEpoch, 8))).expect("commit");
    store.close().expect("close");

    f.delete_anchor();

    let store = f.open(true).expect("open");
    assert_eq!(
        store.outcome().state,
        AnchorState::AnchorMissingIdentityPresent
    );
    assert_eq!(store.outcome().rung, Rung::L4);
    assert!(store.outcome().suspend_granted_authority);
    store.close().expect("close");
}

/// **Attack test — ST-22's payoff, part two.** Anchor and identity both gone is
/// a restored image, and the outcome is re-enrolment rather than a device that
/// runs with no floors at all.
#[test]
fn deleting_the_anchor_and_the_identity_classifies_as_re_enrolment() {
    let f = Fixture::new("anchor-and-identity-gone");
    let store = f.open(false).expect("open");
    assert_eq!(store.outcome().state, AnchorState::AnchorAndIdentityMissing);
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// The ladder: L3
// ---------------------------------------------------------------------------

/// **Attack test — §11.11 rung L3.** A corrupt vault is quarantined (never
/// deleted), a fresh one is created, and **the floors are seeded from the
/// Tier-1 anchor, never from the quarantined file**. Seeding from the file would
/// let an attacker choose the floors by choosing the corruption.
#[test]
fn a_corrupt_vault_is_quarantined_and_the_floors_come_from_tier_1() {
    let f = Fixture::new("l3");
    let mut store = f.open(true).expect("open");
    drive(
        store.commit(
            Transaction::new()
                .write(peer_key(), b"v1".to_vec(), false, 1)
                .advance_floor(FloorId::TrustEpoch, 12),
        ),
    )
    .expect("commit");
    store.close().expect("close");

    // Corrupt the vault beyond its checksum.
    let mut image = std::fs::read(f.paths().vault()).expect("read");
    let n = image.len();
    image[n / 2] ^= 0xff;
    std::fs::write(f.paths().vault(), &image).expect("corrupt");

    let store = f.open(true).expect("open");
    assert!(
        store.outcome().vault_rebuilt,
        "the vault must have been rebuilt"
    );
    assert_eq!(
        store.floors().get(&FloorId::TrustEpoch),
        12,
        "floors must come from the Tier-1 anchor, not from the corrupt file"
    );
    assert!(
        store.get(&peer_key()).expect("get").is_none(),
        "the rebuilt vault starts empty"
    );

    // The quarantined file survives: it is the only evidence of what happened.
    let quarantined: Vec<_> = std::fs::read_dir(f.paths().root())
        .expect("dir")
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("vault.corrupt.")
        })
        .collect();
    assert_eq!(quarantined.len(), 1, "the corrupt vault must be kept");
    store.close().expect("close");
}

// ---------------------------------------------------------------------------
// ST-15 rule 2
// ---------------------------------------------------------------------------

/// **Attack test — ST-15 rule 2.** A vault written by a newer build is refused
/// and **left alone**: "It MUST NOT delete, reset, downgrade, or 'repair' the
/// store. This is what makes an ADR-0021 rollback non-destructive."
#[test]
fn a_vault_from_a_newer_build_is_refused_and_left_untouched() {
    let f = Fixture::new("schema-too-new");
    let mut store = f.open(true).expect("open");
    drive(store.commit(Transaction::new().write(peer_key(), b"v1".to_vec(), false, 1)))
        .expect("commit");
    store.close().expect("close");

    // Rewrite the header's schema_version to a future value.
    let image = std::fs::read(f.paths().vault()).expect("read");
    let mut v = Vault::decode(&image).expect("decode");
    v.schema_version = twinvpn_store::vault::MAX_SUPPORTED_SCHEMA + 1;
    let future_image = v.encode();
    std::fs::write(f.paths().vault(), &future_image).expect("write");

    let err = f.open(true).expect_err("must refuse");
    assert!(matches!(err, StoreError::SchemaTooNew { .. }));
    assert_eq!(err.reason_code().as_str(), "STORE.SCHEMA_TOO_NEW");
    assert_eq!(
        std::fs::read(f.paths().vault()).expect("read"),
        future_image,
        "the store must be byte-identical after a refusal"
    );
    // And the lock was released, so a downgrade-then-upgrade is not blocked by a
    // stale lock from the refused open.
    assert!(!f.paths().lock().exists());
}

// ---------------------------------------------------------------------------
// E3: single opener
// ---------------------------------------------------------------------------

/// E3 and §11.9: two openers are refused, never shared. A second writer is how a
/// multi-key commit stops being atomic.
#[test]
fn a_second_opener_is_refused() {
    let f = Fixture::new("single-opener");
    let first = f.open(true).expect("first");
    let err = f.open(true).expect_err("second must be refused");
    assert!(matches!(
        err,
        StoreError::VaultIo {
            detector: "lock contended"
        }
    ));
    first.close().expect("close");
    // And after a clean close the next open succeeds.
    let again = f.open(true).expect("after close");
    again.close().expect("close");
}

// ---------------------------------------------------------------------------
// CB-6a
// ---------------------------------------------------------------------------

/// CB-6a: "a core-held key … MUST be recorded in `CoreBuildIdentity` (S-46) and
/// surfaced in the diagnostic bundle, so 'this device's vault key was
/// software-held' is a readable fact rather than an inference."
#[test]
fn the_sek_custody_is_a_declared_fact_and_not_an_inference() {
    let f = Fixture::new("custody");
    let store = f.open(true).expect("open");
    let tag = store.outcome().sek_custody.tag();
    assert!(
        tag.starts_with("core-held:"),
        "the mock declares CoreHeld, and the tag must say so: {tag}"
    );
    // The locked-allocator report is carried through, whatever this kernel
    // granted — the value is discrimination, not a claim.
    assert!(store.outcome().sek_custody.locked.is_some());
    store.close().expect("close");
}
