//! `twinvpn-presence` — process entry point.

#![forbid(unsafe_code)]

use std::sync::Arc;

use twinvpn_presence as pr;
use twinvpn_service_common as svc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configuration.
    let cfg = svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        pr::SERVICE_NAME,
        env!("CARGO_PKG_VERSION"),
        pr::COMPONENT_NAME,
        svc::config::RegistryCheck::Required,
    )?;
    let pr_cfg = pr::config::PresenceConfig::load(&svc::config::SystemEnv)?;

    // 2. Metrics, then observability.
    let metrics = svc::metrics::Metrics::new();
    let instance_id = format!("{}-{}", cfg.service_name, std::process::id());
    let obs = svc::obs::init(&cfg.observability_config(&instance_id), metrics.clone())?;

    if pr_cfg.database_url_present {
        // Said out loud at startup rather than left for someone to discover from
        // an empty table: presence is ephemeral by contract and this service
        // writes nothing durable. See README.md §8.
        tracing::warn!(
            twinvpn.outcome = "unused_dependency",
            "TWINVPN_DATABASE_URL is set and is not used: presence records are ephemeral by \
             contract (presence.proto, protocol.md 6.1) and this service has no database client"
        );
    }

    // 3. Health.
    //
    //    `NoControlPlaneCalls`, and `infra/README.md` §5 says `AnyDependency`
    //    with "Postgres reachable". A presence aggregator that reports NOT READY
    //    on a Postgres blip is removed from service, and losing presence must
    //    degrade reconnect LATENCY and never CAPABILITY (architecture.md §2.13).
    //    Since this service holds nothing durable there is no dependency whose
    //    absence could make its answer wrong. Reported in README.md §8.
    // TLS before anything that could serve: a key that will not load must stop
    // the process, not degrade it to a plaintext listener.
    let shared = Arc::new(pr::server::Shared::new(pr_cfg.clone(), metrics.clone())?);
    let listener = tokio::net::TcpListener::bind(pr_cfg.listen_tcp).await?;
    let bound_addr = listener.local_addr()?;

    let probe_state = Arc::clone(&shared);
    let health =
        svc::health::HealthRegistry::builder(svc::health::ReadinessPolicy::NoControlPlaneCalls)
            .readiness(svc::health::FnProbe::new(
                "presence_table",
                svc::health::ProbeKind::Local,
                move || {
                    let s = Arc::clone(&probe_state);
                    async move {
                        let store = s.store.lock().await;
                        if store.len() <= s.config.store.max_devices {
                            svc::health::ProbeOutcome::Ready
                        } else {
                            svc::health::ProbeOutcome::NotReady(
                                svc::codes::RESOURCE_MEMORY_EXHAUSTED,
                            )
                        }
                    }
                },
            ))?
            .liveness(svc::health::FnLiveness::new("accept_loop", || true))
            .build();

    // 4. Shutdown.
    let shutdown = Arc::new(
        svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
            .with_health(health.clone()),
    );
    let handle = shutdown.handle();

    // 5. Admin on :9090.
    let admin = tokio::spawn(svc::admin::serve(
        cfg.admin_addr,
        svc::admin::router(health.clone(), metrics.clone()),
        {
            let h = handle.clone();
            async move { h.draining().await }
        },
    ));

    let sweeper = tokio::spawn(pr::server::sweeper(
        Arc::clone(&shared),
        handle.clone(),
        pr_cfg.sweep_interval,
    ));
    let serving = tokio::spawn(pr::server::serve(
        listener,
        Arc::clone(&shared),
        handle.clone(),
    ));

    tracing::info!(
        twinvpn.outcome = "listening",
        port = bound_addr.port(),
        "presence serving heartbeats"
    );

    // 6. Serve.
    health.set_state(svc::health::ServiceState::Serving);
    svc::shutdown::Shutdown::wait_for_signal().await;
    let report = shutdown.shutdown().await;
    let _ = tokio::join!(admin, sweeper, serving);
    obs.shutdown();
    if !report.drained {
        tracing::warn!(
            twinvpn.outcome = "grace_expired",
            "in-flight work outlived TWINVPN_SHUTDOWN_GRACE_MS"
        );
    }
    Ok(())
}
