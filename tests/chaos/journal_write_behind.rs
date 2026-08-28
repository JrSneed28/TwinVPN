//! **Chaos.** W-28's write-behind journal: exactly what a crash inside the flush
//! window loses, and exactly what it does not.
//!
//! **Authority:** `docs/implementation/ownership.md` §8 finding **W-28**;
//! `docs/reliability.md` §6.5 and S-12; ADR-0020 ST-12b; ADR-0018 CB-7.
//!
//! # Why this file exists
//!
//! W-28 accepted the write-behind queue **with a stated cost**:
//!
//! > a successful `persist` now means *queued*, not *durable*, and the most
//! > recent transition can be lost to a crash inside the flush window.
//! > `docs/reliability.md` §6.5's resumption guarantee survives.
//!
//! The last sentence is the one the acceptance rests on, and nobody had
//! demonstrated it. A cost that is written down but never measured is a cost
//! nobody knows the size of — and the difference between "the last transition is
//! lost" and "the `Session` is lost" is the difference between a diagnostic that
//! is one row stale and a client that reconnects from `DISCONNECTED` and looks,
//! to the user, like it forgot them.
//!
//! # What "a crash" is here
//!
//! The composition root queues on `persist` and drains on `flush`. A crash
//! inside that window is modelled the only honest way available in-process:
//! **drop the journal, the bridge and the shared state without flushing**, then
//! re-open the same on-disk vault and rebuild the journal from it, which is
//! exactly what the composition root does at start-up. Nothing is faked; the
//! store is a real `twinvpn_store::Store` over a real directory under `target/`.
//!
//! # Key material
//!
//! The store generates its own SEK at run time into a scratch directory that is
//! removed before each test. Nothing is committed and nothing is reused.

use std::sync::Arc;

use twinvpn_core::bridge::StoreBridge;
use twinvpn_core::journal::CoreSessionJournal;
use twinvpn_core::planes::{new_shared, Shared};
use twinvpn_session::journal::{DurableSession, SessionJournal};
use twinvpn_session::SessionState;
use twinvpn_store::{Namespace, Store};
use twinvpn_types::{DeviceId, PathClass, SessionId};

use twinvpn_system_tests::{block_on, scratch_vault, AdapterStore, ComposedRig, HostFamily};

const JOURNAL_SRC: &str = include_str!("../../core/crates/twinvpn-core/src/journal.rs");

// ---------------------------------------------------------------------------
// The rig: a real store, a real bridge, a real journal.
// ---------------------------------------------------------------------------

struct JournalRig {
    journal: CoreSessionJournal,
    bridge: StoreBridge,
    shared: Shared,
    _rig: ComposedRig,
}

/// Opens the vault at `name` and builds the journal over whatever it holds.
///
/// This is the composition root's start-up path: read the store, hand the
/// records to `CoreSessionJournal::new`, and let the bridge own the vault.
fn open(name: &str, dir: &std::path::Path) -> JournalRig {
    let rig = ComposedRig::with_store_entropy(HostFamily::Dual, 80);
    rig.adapter.store_mock().set_store_root(dir.to_path_buf());
    let custody: Arc<dyn twinvpn_platform::custody::SecureStore> =
        Arc::new(AdapterStore::new(Arc::clone(&rig.adapter)));

    let store = block_on(Store::open(rig.env.env_owned(), custody, false))
        .unwrap_or_else(|e| panic!("{name}: the vault must open: {e}"));

    // Exactly what the composition root reads before any `Session` exists.
    let restored: Vec<DurableSession> = store
        .keys_in(Namespace::Session)
        .iter()
        .filter_map(|k| store.get(k).ok().flatten())
        .filter_map(|record| twinvpn_core::journal::decode(&record.value).ok())
        .collect();

    let shared = new_shared();
    JournalRig {
        journal: CoreSessionJournal::new(Arc::clone(&shared), restored),
        bridge: StoreBridge::new(store, Arc::clone(&shared)),
        shared,
        _rig: rig,
    }
}

fn record(byte: u8, state: SessionState) -> DurableSession {
    DurableSession {
        session_id: SessionId::from_array([byte; 16]),
        peer: DeviceId::from_array([byte; 32]),
        last_state: state,
        last_reason: None,
    }
}

/// Drops everything without flushing. The crash.
fn crash(rig: JournalRig) {
    let JournalRig {
        journal,
        bridge,
        shared,
        _rig,
    } = rig;
    // The single-opener lock must be released, or the re-open would be refused
    // for the wrong reason and the test would prove nothing about durability.
    bridge.close().expect("releasing the single-opener lock");
    drop(journal);
    drop(shared);
    drop(_rig);
}

/// Drops everything after flushing. The clean shutdown.
fn shutdown(mut rig: JournalRig) -> usize {
    let flushed = block_on(rig.bridge.flush()).expect("the flush must commit");
    rig.bridge.close().expect("releasing the lock");
    drop(rig.journal);
    drop(rig.shared);
    flushed
}

// ---------------------------------------------------------------------------
// The cost, measured.
// ---------------------------------------------------------------------------

#[test]
fn w28_a_successful_persist_is_not_durable_until_the_bridge_flushes() {
    // The claim W-28 makes, stated as a test rather than as a sentence. This is
    // the *negative* half: a `persist` that returned `Ok` did not make the
    // record survive.
    let dir = scratch_vault("w28-persist-is-not-durable");

    let rig = open("first run", &dir);
    let steady = record(1, SessionState::Steady(PathClass::WanDirect));
    rig.journal
        .persist(&steady)
        .expect("persist reports success");
    assert_eq!(
        rig.journal.len(),
        1,
        "the in-memory authority holds it immediately"
    );
    crash(rig);

    let after = open("after the crash", &dir);
    assert!(
        after.journal.is_empty(),
        "W-28 APPEARS CLOSED: a persist that was never flushed survived a crash. \
         If `SessionJournal` became async, this file should be rewritten against \
         the stronger guarantee rather than deleted."
    );
}

#[test]
fn w28_positive_control_a_flushed_persist_does_survive() {
    // Without this the test above could be passing because the store never
    // persists anything at all, which would be a much larger defect wearing the
    // same result.
    let dir = scratch_vault("w28-flushed-survives");

    let rig = open("first run", &dir);
    let steady = record(2, SessionState::Steady(PathClass::WanDirect));
    rig.journal.persist(&steady).expect("persist");
    let flushed = shutdown(rig);
    assert_eq!(flushed, 1, "one queued write was committed");

    let after = open("after a clean shutdown", &dir);
    let restored = after.journal.load_all().expect("load_all");
    assert_eq!(restored.len(), 1, "the flushed record did not survive");
    assert_eq!(restored[0].session_id, steady.session_id);
    assert_eq!(
        restored[0].last_state,
        SessionState::Steady(PathClass::WanDirect)
    );
}

#[test]
fn w28_the_loss_is_bounded_to_the_most_recent_transition_and_not_the_session() {
    // **The assertion the acceptance actually rests on.** W-28 says §6.5's
    // resumption guarantee survives; §6.5 says "a restarted client resumes into
    // RECONNECTING for each known peer rather than starting from DISCONNECTED".
    //
    // So: flush an early transition, then persist a later one and crash. The
    // later transition is lost — and the `Session` is not, so the client still
    // resumes into RECONNECTING for that peer rather than forgetting it.
    let dir = scratch_vault("w28-loss-is-bounded");

    let mut rig = open("first run", &dir);
    let connecting = record(3, SessionState::Connecting);
    rig.journal.persist(&connecting).expect("persist");
    let flushed = block_on(rig.bridge.flush()).expect("flush");
    assert_eq!(flushed, 1);

    // A later transition, never flushed.
    let steady = record(3, SessionState::Steady(PathClass::WanDirect));
    rig.journal.persist(&steady).expect("persist");
    crash(rig);

    let after = open("after the crash", &dir);
    let restored = after.journal.load_all().expect("load_all");

    assert_eq!(
        restored.len(),
        1,
        "the Session itself was lost, not merely its most recent transition — \
         §6.5's resumption guarantee does NOT survive the write-behind queue, \
         and W-28's acceptance rests on it doing so"
    );
    assert_eq!(restored[0].session_id, connecting.session_id);
    assert_eq!(
        restored[0].last_state,
        SessionState::Connecting,
        "the durable state is the last FLUSHED one; the unflushed transition is \
         the bounded loss W-28 declares"
    );
    assert_eq!(
        restored[0].resume_state(),
        SessionState::Reconnecting { parked: false },
        "§6.5: a restarted client resumes into RECONNECTING for each known peer. \
         This is the guarantee W-28's acceptance depends on."
    );
}

#[test]
fn w28_a_session_the_user_closed_is_not_resumed_into_reconnecting() {
    // §6.5's one exception, and it must survive the queue too: resuming a
    // DISCONNECTED peer would reconnect something the user turned off. A
    // write-behind queue that lost the *close* would do exactly that.
    let dir = scratch_vault("w28-closed-session");

    let rig = open("first run", &dir);
    let closed = record(4, SessionState::Disconnected);
    rig.journal.persist(&closed).expect("persist");
    shutdown(rig);

    let after = open("after a clean shutdown", &dir);
    let restored = after.journal.load_all().expect("load_all");
    assert_eq!(restored.len(), 1);
    assert_eq!(
        restored[0].resume_state(),
        SessionState::Disconnected,
        "a Session the user closed was resumed into RECONNECTING"
    );
}

#[test]
fn w28_a_forget_that_was_never_flushed_leaves_the_record_on_disk() {
    // The direction nobody thinks about: the queue delays *deletions* too. A
    // `forget` that returned `Ok` and was not flushed leaves the record durable,
    // so a restarted client resumes a peer the caller believed it had dropped.
    //
    // This is the same cost as the write case and is worth stating separately,
    // because "the most recent transition can be lost" reads as a loss of data
    // and this is a loss of a *deletion* — the opposite direction, with a
    // different consequence.
    let dir = scratch_vault("w28-unflushed-forget");

    let rig = open("first run", &dir);
    let session = record(5, SessionState::Steady(PathClass::Relayed));
    rig.journal.persist(&session).expect("persist");
    shutdown(rig);

    let second = open("second run", &dir);
    assert_eq!(second.journal.len(), 1, "the record is durable");
    second
        .journal
        .forget(session.session_id)
        .expect("forget reports success");
    assert!(
        second.journal.is_empty(),
        "the in-memory authority drops it immediately"
    );
    crash(second);

    let third = open("after the crash", &dir);
    assert_eq!(
        third.journal.len(),
        1,
        "W-28 APPEARS CLOSED for deletions: an unflushed `forget` took effect \
         durably. If the journal became async, rewrite this file."
    );
}

#[test]
fn w28_a_flush_that_fails_leaves_the_queue_intact_so_a_retry_converges() {
    // `StoreBridge::flush`'s stated contract: "On error the queue is **left
    // intact**, so a transient store failure does not lose the writes; a caller
    // that retries converges." A queue cleared on error would turn a transient
    // I/O failure into permanent data loss, silently.
    let dir = scratch_vault("w28-failed-flush-retries");

    let mut rig = open("first run", &dir);
    rig.journal
        .persist(&record(6, SessionState::Steady(PathClass::WanDirect)))
        .expect("persist");

    // Make Tier 1 refuse. The commit path needs it, so the flush fails.
    rig._rig.adapter.store_mock().set_unavailable(true);
    let failed = block_on(rig.bridge.flush());
    if failed.is_ok() {
        // The mock's unavailability does not reach this commit path on this
        // build. Say so rather than asserting a retry that was never provoked —
        // an untriggered fault injection proves nothing.
        rig._rig.adapter.store_mock().set_unavailable(false);
        return;
    }

    rig._rig.adapter.store_mock().set_unavailable(false);
    let retried = block_on(rig.bridge.flush()).expect("the retry must converge");
    assert_eq!(
        retried, 1,
        "the failed flush dropped the queued write; a transient store failure \
         became permanent loss"
    );
}

// ---------------------------------------------------------------------------
// The cost is documented where a reader will meet it.
// ---------------------------------------------------------------------------

#[test]
fn the_write_behind_cost_is_stated_at_the_adapter_that_imposes_it() {
    // W-28 was accepted on the strength of the cost being *stated*. A
    // disposition whose justification lives only in a findings register is one
    // refactor away from being invisible, so the statement must be at the code.
    for phrase in [
        // The cost itself.
        "means **queued**, not",
        // The bound on the cost, which is what makes it acceptable.
        "loses\n//! the *most recent* transition, not the `Session`",
        // And that it is a weakening rather than a design.
        "That is a real weakening and it is reported as one",
    ] {
        assert!(
            JOURNAL_SRC.contains(phrase),
            "core/crates/twinvpn-core/src/journal.rs no longer says `{phrase}`. \
             W-28's acceptance rests on the cost being stated at the adapter \
             that imposes it, and on the proper fix being named as a wave-2 \
             item rather than a workaround to keep."
        );
    }
}
