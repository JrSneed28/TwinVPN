//! `twinvpn-relay` — process entry point.
//!
//! The wiring order is `twinvpn-service-common`'s README §2: configuration
//! before observability, health before shutdown, the admin listener last.
//!
//! Two things differ from the other five services, and both are load-bearing:
//!
//! 1. **`ReadinessPolicy::NoControlPlaneCalls`.** Structural I5: the registry
//!    *refuses* a probe declaring `ProbeKind::ControlPlane`, so a relay cannot
//!    acquire a control-plane readiness dependency by accident. ADR-0005 §11.3
//!    and architecture A-12: admission is offline, so a relay must come up and
//!    stay up with the whole control plane down.
//! 2. **The issuer key set is loaded at startup and a failure is fatal**, but an
//!    *empty* set is not. `infra/scripts/bootstrap-local.sh` ships `issuers: []`
//!    on purpose; a relay with no issuers is correctly configured and correctly
//!    admits nothing. A relay whose key file is missing or corrupt is genuinely
//!    broken and refuses to start.
#![forbid(unsafe_code)]

use std::sync::Arc;

use twinvpn_relay::config::RelayConfig;
use twinvpn_relay::drr::TwoTierDrr;
use twinvpn_relay::issuer::IssuerKeySet;
use twinvpn_relay::loop_udp::{serve_udp, RelayRuntime};
use twinvpn_relay::net::CarriageSet;
use twinvpn_relay::provider::CryptoProvider;
use twinvpn_relay::pump::LegRegistry;
use twinvpn_relay::RelayEngine;
use twinvpn_service_common as svc;

/// The leg-registry ceiling.
///
/// A leg is created by an unauthenticated source completing a handshake, so an
/// unbounded map keyed by source address is a remote memory-exhaustion primitive
/// (`ownership.md` §6 rule 10). 65 536 legs is the same order as the relay-wide
/// half-flow ceiling and is stated as an addition, like that one.
const MAX_LEGS: usize = 65_536;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configuration. A missing file, an altered frozen limit, or
    //    TWINVPN_RELAY_RETAIN_PEER_PAIR=true fails HERE.
    let cfg = svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        "relay",
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_RELAY_SERVER",
        svc::config::RegistryCheck::Required,
    )?;
    let relay_cfg = RelayConfig::load(&svc::config::SystemEnv)?;

    // 2. Metrics, then observability.
    let metrics = svc::metrics::Metrics::new();
    let obs = svc::obs::init(
        &cfg.observability_config(&relay_cfg.relay_id_hex),
        metrics.clone(),
    )?;

    // 3. The issuer key set. Empty is legal and means "admit nothing".
    let issuers = IssuerKeySet::load(&relay_cfg.issuer_keys_path, &relay_cfg.operator_group_id)?;
    if issuers.is_empty() {
        tracing::warn!(
            outcome = "closed",
            "issuer key set is empty: no RelayCapabilityToken can verify, so this \
             relay will admit no flow. That is the fail-closed default."
        );
    }

    // 4. The cryptographic provider. `twinvpn-crypto` (ADR-0018 CD-I2, DP-8):
    //    COSE_Sign1 verification over the received octets, and the daily
    //    relay_sub digest. The frame MAC is not bound in this build and says so,
    //    once, rather than presenting as a flood of dropped frames.
    let crypto = CryptoProvider::new();
    if !crypto.frame_mac_available() {
        tracing::error!(
            outcome = "partial_provider",
            "the keyed BLAKE2s frame MAC (ADR-0005 §9.1) is not available from \
             twinvpn-crypto in this build: admission and the epoch floor are live, \
             but NO DATA FRAME WILL BE FORWARDED. See services/relay/README.md §8."
        );
    }

    // 5. Carriages. A carriage this build cannot serve is recorded, not faked.
    let carriages = CarriageSet::bind(&relay_cfg).await?;
    for (carriage, why) in &carriages.unavailable {
        tracing::error!(
            outcome = "unavailable",
            carriage = carriage.as_str(),
            detail = why.as_str(),
            "configured carriage is not served; readiness will stay RED"
        );
    }

    // 6. The runtime the receive loop drives. `legs` starts EMPTY and stays
    //    empty: establishing one needs the Noise_IK handshake (R-UDP) or an RFC
    //    8446 exporter (R-QUIC/R-TLS), neither of which exists in this build. A
    //    relay therefore forwards nothing, which is the fail-closed direction and
    //    is stated once here rather than inferred from silence.
    let runtime = Arc::new(std::sync::Mutex::new(RelayRuntime {
        engine: RelayEngine::new(relay_cfg.clone(), issuers, 0),
        legs: LegRegistry::new(MAX_LEGS),
        scheduler: TwoTierDrr::with_default_quantum(),
    }));
    tracing::warn!(
        outcome = "no_legs",
        "no leg handshake is implemented in this build, so no device can \
         establish K_leg and every received frame is dropped with zero bytes in \
         reply. See services/relay/README.md §11."
    );

    // 7. Health. NoControlPlaneCalls REFUSES a ProbeKind::ControlPlane probe,
    //    which is what makes I5 structural rather than remembered.
    let issuer_probe = {
        let runtime = Arc::clone(&runtime);
        svc::health::FnProbe::new("issuer_keys", svc::health::ProbeKind::Local, move || {
            // Loaded and parsable — NOT non-empty. infra/README.md §5.
            let ok = runtime.lock().is_ok();
            async move {
                if ok {
                    svc::health::ProbeOutcome::Ready
                } else {
                    svc::health::ProbeOutcome::NotReady(
                        twinvpn_types::codes::INTERNAL_INVARIANT_VIOLATED,
                    )
                }
            }
        })
    };
    let all_bound = carriages.all_configured_carriages_bound();
    let carriage_probe = svc::health::FnProbe::new(
        "carriages_bound",
        svc::health::ProbeKind::Local,
        move || async move {
            if all_bound {
                svc::health::ProbeOutcome::Ready
            } else {
                svc::health::ProbeOutcome::NotReady(twinvpn_types::codes::RELAY_NONE_REACHABLE)
            }
        },
    );

    let health =
        svc::health::HealthRegistry::builder(svc::health::ReadinessPolicy::NoControlPlaneCalls)
            .readiness(issuer_probe)?
            .readiness(carriage_probe)?
            .liveness(svc::health::FnLiveness::new("forwarder", || true))
            .build();

    // 8. Shutdown, wired to health so the drain turns /readyz red immediately.
    let shutdown = Arc::new(
        svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
            .with_health(health.clone()),
    );

    // The relay's drain is ADR-0005 §8's, not a generic one: it announces one
    // deadline to every bound flow and then keeps carrying until that deadline.
    {
        let runtime = Arc::clone(&runtime);
        let deadline = shutdown.drain_deadline_ms();
        shutdown.register_teardown(20, "relay_drain", move || {
            let runtime = Arc::clone(&runtime);
            svc::shutdown::futures_step::boxed(async move {
                if let Ok(mut rt) = runtime.lock() {
                    let e = &mut rt.engine;
                    let (plan, flows) = e.begin_drain(0, deadline);
                    tracing::info!(
                        outcome = "draining",
                        "announced a {} ms drain deadline to {} flows",
                        plan.deadline_ms(),
                        flows.len()
                    );
                }
            })
        });
    }
    shutdown.register_teardown(90, "otel", || svc::shutdown::futures_step::boxed(async {}));

    let handle = shutdown.handle();
    let admin = tokio::spawn(svc::admin::serve(
        cfg.admin_addr,
        svc::admin::router(health.clone(), metrics.clone()),
        {
            let h = handle.clone();
            async move { h.draining().await }
        },
    ));

    // 9. The receive loops, one per bound socket. Each reads a datagram, calls
    //    the synchronous pump, and writes AT MOST ONE datagram — the shape of
    //    ADR-0005 §11.5's amplification factor of exactly 1.0.
    let provider: Arc<dyn twinvpn_relay::RelayCrypto> = Arc::new(crypto);
    let listening = carriages.bound.len();
    let mut pumps = Vec::new();
    for bound in carriages.bound {
        let runtime = Arc::clone(&runtime);
        let provider = Arc::clone(&provider);
        let h = handle.clone();
        let addr = bound.local_addr;
        let family = bound.families.as_label();
        pumps.push(tokio::spawn(async move {
            tracing::info!(
                outcome = "listening",
                address_family = family,
                "R-UDP receive loop on {addr}"
            );
            serve_udp(
                Arc::new(bound.socket),
                runtime,
                provider,
                // The packet path's own clock. `WallClock` is evidence only
                // (ADR-0018 CD-1), so this is a monotonic offset, not a timestamp.
                {
                    let started = std::time::Instant::now();
                    move || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
                },
                async move { h.draining().await },
            )
            .await;
        }));
    }

    health.set_state(svc::health::ServiceState::Serving);
    tracing::info!(
        outcome = "serving",
        "relay {} in region {} failure domain {} on {} carriage socket(s)",
        relay_cfg.relay_id_hex,
        relay_cfg.region_id,
        relay_cfg.failure_domain,
        listening
    );

    svc::shutdown::Shutdown::wait_for_signal().await;
    let report = shutdown.shutdown().await;
    let _ = admin.await;
    for p in pumps {
        let _ = p.await;
    }
    obs.shutdown();
    if !report.drained {
        tracing::warn!(
            outcome = "grace_expired",
            "shutdown grace expired mid-drain"
        );
    }
    Ok(())
}
