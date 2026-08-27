//! **The outage.** A total control-plane outage never prevents re-establishing a
//! session with an already-known `TrustedPeer`.
//!
//! **Authority:** invariant **I5**, `docs/architecture.md` §4.4 (how I5 is
//! enforced) and §4.4.5 (the negative conformance requirement),
//! `docs/reliability.md` §9.1 (the three-way split), §9.2 (grant/deny asymmetry
//! — *not* a credential cliff), §9.4 (what the user is told).
//!
//! The sibling file `replay_rollback_publisher.rs` carries the replay, rollback,
//! wrong-publisher and compaction scenarios.

use std::sync::Arc;

use twinvpn_cp_client::testing::{test_env_with_clock, RecordingTransport};
use twinvpn_cp_client::{
    cache, CachedPeer, ChannelHealth, ClientParts, ControlPlaneClient, Cursor, ResumeOutcome, Rung,
    TrustStateThresholds,
};
use twinvpn_types::{
    DeviceId, Endpoint, IpAddr, OverlayAddresses, Port, TwinnetId, V4Addr, V6Addr,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn twinnet() -> TwinnetId {
    TwinnetId::new("tn-integration").expect("valid")
}

fn block_on<F>(env: &twinvpn_env::Env, fut: F) -> F::Output
where
    F: core::future::Future + Send,
    F::Output: Send,
{
    let cell = Arc::new(std::sync::Mutex::new(None));
    let sink = Arc::clone(&cell);
    env.runtime().block_on(Box::pin(async move {
        let out = fut.await;
        *sink.lock().expect("not poisoned") = Some(out);
    }));
    let mut guard = cell.lock().expect("not poisoned");
    guard.take().expect("the future completed")
}

fn client(
    env: &twinvpn_env::Env,
    transport: Arc<dyn twinvpn_cp_client::ControlTransport>,
    cursor: Cursor,
) -> ControlPlaneClient {
    ControlPlaneClient::new(ClientParts {
        env: env.clone(),
        transport,
        twinnet_id: twinnet(),
        sender_id: "twd1integration".to_owned(),
        coordination_endpoints: vec!["cp.example.invalid".to_owned()],
        families: twinvpn_cp_client::AttachFamilies {
            v4: true,
            v6: true,
            nat64: false,
        },
        cursor,
        mobile_background: false,
    })
}

/// A peer that was fully materialised before the outage began — the
/// `architecture.md` §4.4.1 pre-materialization rule, from this crate's side.
fn known_peer() -> CachedPeer {
    CachedPeer {
        device_id: DeviceId::from_array([0xA1; 32]),
        generation: 2,
        tk_generation: 5,
        tunnel_key_binding_verified: true,
        endpoints: vec![Endpoint::new(
            IpAddr::V4(V4Addr::from_octets([203, 0, 113, 7])),
            Port::new(51_820).expect("non-zero"),
        )],
        overlay: OverlayAddresses {
            v4: V4Addr::from_octets([100, 64, 0, 9]),
            v6: V6Addr::new(
                [
                    0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
                ],
                None,
            )
            .expect("product ULA"),
        },
    }
}

// ---------------------------------------------------------------------------
// THE OUTAGE
// ---------------------------------------------------------------------------

#[test]
fn a_total_control_plane_outage_still_permits_reconnect_to_a_known_peer() {
    let (env, clock) = test_env_with_clock();
    // Every rung blackholed: rendezvous, presence and the coordination API are
    // all unreachable. This is `architecture.md` §4.4.5's negative conformance
    // shape, from the control-plane client's side.
    let transport = Arc::new(RecordingTransport::always_failing());
    let mut c = client(
        &env,
        Arc::clone(&transport) as Arc<_>,
        Cursor::restored(9_182),
    );

    let err = match block_on(&env, c.attach()) {
        Ok(_) => panic!("the transport is blackholed"),
        Err(err) => err,
    };

    // (a) The outage is named, not rendered as a connection failure.
    assert_eq!(err.reason_code().as_str(), "CONTROL.UNREACHABLE");
    assert!(!err.reason_code().terminal());
    assert_eq!(
        err.reason_code().severity(),
        twinvpn_types::ErrorSeverity::Warn,
        "reliability.md §9.4: surfacing this as a terminal failure is a defect"
    );

    // (b) Every rung was tried and each fall-through is observable.
    assert_eq!(
        transport.attempts(),
        vec![Rung::Quic, Rung::Http2Tcp, Rung::Http1LongPoll, Rung::Proxy]
    );

    // (c) The data plane is untouched. This is the whole of I5.
    assert!(c.health().permits_data_plane_reconnect());
    assert_eq!(c.health(), ChannelHealth::Unreachable);
    assert!(err.permits_offline_reconnect());

    // (d) The cached peer alone is sufficient to re-establish.
    let peer = known_peer();
    assert!(
        peer.supports_offline_reconnect(),
        "reliability.md §9.1: a NEW Session to an existing TrustedPeer continues, indefinitely"
    );
    assert!(cache::cached_peer_set_usable_during_outage());

    // (e) An outage of unbounded length changes none of that. Thirty-one days
    //     of suspend advances the elapsed and wall clocks and no monotonic time,
    //     which is exactly the laptop-in-a-bag case.
    clock.suspend(core::time::Duration::from_secs(31 * 24 * 3_600));
    let thresholds = TrustStateThresholds::ADR_0007;
    let band = thresholds.band_of(core::time::Duration::from_secs(31 * 24 * 3_600));
    assert_eq!(band, twinvpn_cp_client::TrustStateBand::Expired);
    assert!(
        band.baseline_peer_connectivity(),
        "past T_TRUST_HARD, baseline reachability is STILL permitted"
    );
    assert!(
        !band.elevated_authority(),
        "grants suspend — that is the whole of the asymmetry"
    );

    // (f) The cursor survived, so the next attach RESUMES rather than reloads.
    assert_eq!(
        c.resume_plan(),
        ResumeOutcome::Resume {
            from_net_seq: 9_182
        }
    );
}

#[test]
fn an_outage_never_widens_an_authorization() {
    // The negative half of the asymmetry, asserted over every document class.
    for doc in [
        twinvpn_cp_client::DocumentType::PolicyBundle,
        twinvpn_cp_client::DocumentType::OwnerTrustAnchor,
        twinvpn_cp_client::DocumentType::TrustEpochBundle,
        twinvpn_cp_client::DocumentType::RelayMap,
        twinvpn_cp_client::DocumentType::RelayEpochFloor,
        twinvpn_cp_client::DocumentType::NetworkContract,
        twinvpn_cp_client::DocumentType::Membership,
    ] {
        let effect = cache::expiry_effect(doc);
        assert!(!effect.can_widen_authorization());
        assert!(!effect.can_tear_down_a_session());
    }
}
