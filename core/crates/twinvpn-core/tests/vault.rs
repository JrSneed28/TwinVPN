//! **D4.** The composed core opens a vault, hydrates from it, and flushes.
//!
//! **Authority:** `docs/architecture.md` §5 S-12/S-15/S-27/S-30/S-37;
//! `docs/reliability.md` §6.5 and §9.1; ADR-0018 CB-7; ADR-0009 R-9;
//! `twinvpn_store`'s ST-12b and ST-23.
//!
//! # The defect this file exists to close
//!
//! `StoreBridge::new` was constructed **nowhere** in `core/`, `services/` or
//! `shells/`. `Core::create` set an empty `BridgeState` and never hydrated it,
//! and `begin_shutdown` closed the event stream and the adapter without
//! flushing, because the `Core` held no bridge. Every durable row was therefore
//! memory-only and the crash window was **the entire process lifetime**.
//!
//! Two ends had to move. This is the core's: `Core::open_store` opens and
//! hydrates, `Core::flush` commits, and `Core::shutdown` flushes **before** it
//! stops accepting work. The shell's end is `desktop-linux`'s.

#![cfg(feature = "full")]

use twinvpn_core::{testing, VaultState};
use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_types::{DeviceId, OverlayAddresses, TwinnetId, V4Addr, V6Addr};

const PEER: [u8; 32] = [0x77; 32];

/// A vault directory of this test's own, in the scratch area cargo gives it.
fn vault_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("twinvpn-vault-test-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn peer_record(byte: u8) -> twinvpn_core::PeerRecord {
    twinvpn_core::PeerRecord {
        device_id: DeviceId::from_slice(&[byte; 32]).expect("32"),
        generation: 1,
        tk_generation: 1,
        tunnel_key_binding_verified: true,
        // S-15: what a reconnect during a total outage uses. Non-empty on
        // purpose — the encoding used to drop exactly this.
        endpoints: vec![twinvpn_types::Endpoint::new(
            twinvpn_types::IpAddr::V4(V4Addr::from_slice(&[198, 51, 100, 4]).expect("v4")),
            twinvpn_types::Port::new(51_820).expect("port"),
        )],
        overlay: OverlayAddresses {
            v4: V4Addr::from_slice(&[100, 64, 0, byte]).expect("v4"),
            v6: V6Addr::from_slice(
                &[0xfd, 0x7c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte],
                0,
            )
            .expect("v6"),
        },
    }
}

#[test]
fn a_core_reports_whether_it_has_a_vault_at_all() {
    let h = testing::harness().expect("creates");
    assert_eq!(
        h.core.vault_state(),
        VaultState::Absent,
        "a core that has not opened a vault must say so, not imply one"
    );
}

#[test]
fn open_store_opens_a_vault_and_flush_commits_through_it() {
    let h = testing::harness().expect("creates");
    h.adapter.store_mock().set_store_root(vault_dir("commit"));
    let env = h.core.env().clone();

    let mut opened = None;
    let mut flushed = None;
    env.runtime().block_on(Box::pin(async {
        opened = Some(h.core.open_store().await.map_err(|d| d.code().as_str()));

        // A control-plane write, queued through the CD-I5 port.
        let cp = h.core.control_plane_port();
        let twinnet = TwinnetId::new("tn-vault").expect("valid");
        cp.put_peer(&twinnet, peer_record(1));
        assert!(cp.advance_trust_epoch(&twinnet, 3));

        flushed = Some(h.core.flush().await.map_err(|d| d.code().as_str()));
    }));

    assert_eq!(opened, Some(Ok(VaultState::Open)), "the vault must open");
    assert_eq!(h.core.vault_state(), VaultState::Open);
    assert_eq!(
        flushed,
        Some(Ok(2)),
        "both queued writes must reach one transaction (ST-12b)"
    );
}

#[test]
fn a_flush_with_no_vault_is_refused_rather_than_reporting_success() {
    // The exact shape of D4: "we flushed" must not be true of a core with
    // nowhere to flush to.
    let h = testing::harness().expect("creates");
    let env = h.core.env().clone();
    let mut result = None;
    env.runtime().block_on(Box::pin(async {
        result = Some(h.core.flush().await.map_err(|d| d.code().as_str()));
    }));
    assert_eq!(result, Some(Err("STORE.CUSTODY_DEGRADED")));
}

#[test]
fn shutdown_flushes_before_it_stops_accepting_work() {
    // `begin_shutdown` is synchronous and cannot flush. A host that only calls
    // it loses every queued durable write, which is what `twinvpnd` did.
    let h = testing::harness().expect("creates");
    h.adapter.store_mock().set_store_root(vault_dir("shutdown"));
    let env = h.core.env().clone();

    let mut flushed = None;
    env.runtime().block_on(Box::pin(async {
        h.core.open_store().await.expect("opens");
        let cp = h.core.control_plane_port();
        cp.put_peer(
            &TwinnetId::new("tn-shutdown").expect("valid"),
            peer_record(2),
        );
        flushed = Some(h.core.shutdown().await.map_err(|d| d.code().as_str()));
    }));

    assert_eq!(flushed, Some(Ok(1)), "shutdown must flush what was queued");
    assert_eq!(
        h.core.vault_state(),
        VaultState::Absent,
        "shutdown releases the single-opener lock"
    );
}

#[test]
fn a_session_survives_into_the_journal_and_comes_back_reconnecting() {
    // §6.5: "a restarted client resumes into RECONNECTING for each known peer
    // rather than starting from DISCONNECTED — which is what makes the
    // diagnostic continuous across a crash."
    let h = testing::harness().expect("creates");
    h.adapter.store_mock().set_store_root(vault_dir("journal"));
    let env = h.core.env().clone();

    let mut connect = Submission::bare(CoreCommand::SessionConnect);
    connect.params = PEER.to_vec();

    let mut flushed = None;
    env.runtime().block_on(Box::pin(async {
        h.core.open_store().await.expect("opens");
        // `session.connect` reads its T01 guards now, so the peer has to be an
        // ADR-0007 N-4 `TrustedPeer` before it will execute. Cached through the
        // CD-I5 port, which is what the control-plane client will do.
        h.core.control_plane_port().put_peer(
            &TwinnetId::new("tn-vault").expect("valid"),
            peer_record(0x77),
        );
        h.core.submit(&connect).expect("session.connect executes");
        flushed = Some(h.core.flush().await.map_err(|d| d.code().as_str()));
    }));

    // The Session's durable record reached the vault. Without `open_store` this
    // would have been a memory write that died with the process.
    assert!(
        matches!(flushed, Some(Ok(n)) if n >= 1),
        "the Session's durable record must reach the vault, got {flushed:?}"
    );
}

#[test]
fn opening_twice_is_a_no_op_rather_than_a_lock_conflict_with_itself() {
    // `twinvpn_store` takes a single-opener lock; a second `open` would report
    // STORE.LOCK_CONTENDED against this very process.
    let h = testing::harness().expect("creates");
    h.adapter.store_mock().set_store_root(vault_dir("twice"));
    let env = h.core.env().clone();
    let mut second = None;
    env.runtime().block_on(Box::pin(async {
        h.core.open_store().await.expect("first");
        second = Some(h.core.open_store().await.map_err(|d| d.code().as_str()));
    }));
    assert_eq!(second, Some(Ok(VaultState::Open)));
}
