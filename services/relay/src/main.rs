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
use twinvpn_relay::issuer::IssuerKeySet;
use twinvpn_relay::net::CarriageSet;
use twinvpn_relay::RelayEngine;
use twinvpn_service_common as svc;

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

    // 4. Carriages. A carriage this build cannot serve is recorded, not faked.
    let carriages = CarriageSet::bind(&relay_cfg).await?;
    for (carriage, why) in &carriages.unavailable {
        tracing::error!(
            outcome = "unavailable",
            carriage = carriage.as_str(),
            detail = why.as_str(),
            "configured carriage is not served; readiness will stay RED"
        );
    }

    let engine = Arc::new(std::sync::Mutex::new(RelayEngine::new(
        relay_cfg.clone(),
        issuers,
        0,
    )));

    // 5. Health. NoControlPlaneCalls REFUSES a ProbeKind::ControlPlane probe,
    //    which is what makes I5 structural rather than remembered.
    let issuer_probe = {
        let engine = Arc::clone(&engine);
        svc::health::FnProbe::new("issuer_keys", svc::health::ProbeKind::Local, move || {
            // Loaded and parsable — NOT non-empty. infra/README.md §5.
            let ok = engine.lock().is_ok();
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

    // 6. Shutdown, wired to health so the drain turns /readyz red immediately.
    let shutdown = Arc::new(
        svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
            .with_health(health.clone()),
    );

    // The relay's drain is ADR-0005 §8's, not a generic one: it announces one
    // deadline to every bound flow and then keeps carrying until that deadline.
    {
        let engine = Arc::clone(&engine);
        let deadline = shutdown.drain_deadline_ms();
        shutdown.register_teardown(20, "relay_drain", move || {
            let engine = Arc::clone(&engine);
            svc::shutdown::futures_step::boxed(async move {
                if let Ok(mut e) = engine.lock() {
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

    health.set_state(svc::health::ServiceState::Serving);
    tracing::info!(
        outcome = "serving",
        "relay {} in region {} failure domain {} on {} carriage socket(s)",
        relay_cfg.relay_id_hex,
        relay_cfg.region_id,
        relay_cfg.failure_domain,
        carriages.bound.len()
    );

    svc::shutdown::Shutdown::wait_for_signal().await;
    let report = shutdown.shutdown().await;
    let _ = admin.await;
    obs.shutdown();
    if !report.drained {
        tracing::warn!(
            outcome = "grace_expired",
            "shutdown grace expired mid-drain"
        );
    }
    Ok(())
}
