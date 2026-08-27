//! `twinvpn-relay-health` — process entry point.
//!
//! Wiring order is `twinvpn-service-common`'s README §2. Readiness is
//! `infra/README.md` §5's for this service: *Postgres reachable*.
//!
//! Note what readiness is **not**: it is not "targets reachable". A relay-health
//! service whose probe targets are all down is working perfectly — it is reporting
//! that they are down. Tying its own readiness to the fleet's would make one
//! relay's outage look like this service's, and would take the aggregate offline
//! at exactly the moment it is most useful.
#![forbid(unsafe_code)]

use std::sync::{Arc, RwLock};

use twinvpn_relay_health::aggregate::Aggregate;
use twinvpn_relay_health::config::HealthConfig;
use twinvpn_service_common as svc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        "relay-health",
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_RELAY_SELECTION",
        svc::config::RegistryCheck::Required,
    )?;
    let hc = HealthConfig::load(&svc::config::SystemEnv)?;

    let metrics = svc::metrics::Metrics::new();
    let obs = svc::obs::init(&cfg.observability_config("relay-health"), metrics.clone())?;

    let aggregate = Arc::new(RwLock::new(Aggregate::new(hc.thresholds)));

    // Readiness: this process can serve its aggregate. The aggregate being
    // EMPTY is not unready — an empty aggregate reports UNKNOWN everywhere,
    // which costs a ranking exactly nothing (S-10).
    let ready = {
        let aggregate = Arc::clone(&aggregate);
        svc::health::FnProbe::new("aggregate", svc::health::ProbeKind::Local, move || {
            let ok = aggregate.read().is_ok();
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

    let health = svc::health::HealthRegistry::builder(svc::health::ReadinessPolicy::AnyDependency)
        .readiness(ready)?
        .liveness(svc::health::FnLiveness::new("prober", || true))
        .build();

    let shutdown = Arc::new(
        svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
            .with_health(health.clone()),
    );
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
        "relay-health probing {} admin listener(s) every {} ms",
        hc.targets.len(),
        hc.probe_interval_ms
    );
    if hc.targets.is_empty() {
        tracing::warn!(
            outcome = "no_targets",
            "no probe targets configured: every relay will report UNKNOWN, which \
             contributes a score delta of exactly zero"
        );
    }

    svc::shutdown::Shutdown::wait_for_signal().await;
    let _report = shutdown.shutdown().await;
    let _ = admin.await;
    obs.shutdown();
    Ok(())
}
