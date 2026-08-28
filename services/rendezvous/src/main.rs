//! `twinvpn-rendezvous` — process entry point.
//!
//! Wiring order is `twinvpn-service-common` §2's, and it matters: configuration
//! before observability (the log level comes from it), health before shutdown
//! (the drain turns `/readyz` red), and the admin listener last so it never
//! reports ready before the service can serve.

#![forbid(unsafe_code)]

use std::sync::Arc;

use twinvpn_rendezvous as rz;
use twinvpn_service_common as svc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configuration. A missing TLS file or an overridden frozen bound fails
    //    HERE, before a socket exists.
    let cfg = svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        rz::SERVICE_NAME,
        env!("CARGO_PKG_VERSION"),
        rz::COMPONENT_NAME,
        svc::config::RegistryCheck::Required,
    )?;
    let rz_cfg = rz::config::RendezvousConfig::load(&svc::config::SystemEnv)?;

    // 2. Metrics, then observability.
    let metrics = svc::metrics::Metrics::new();
    let instance_id = format!("{}-{}", cfg.service_name, std::process::id());
    let obs = svc::obs::init(&cfg.observability_config(&instance_id), metrics.clone())?;

    // 3. Health.
    //
    //    `ReadinessPolicy::NoControlPlaneCalls` is deliberate and diverges from
    //    `infra/README.md` §5, which lists this service as `AnyDependency` with
    //    "the control-plane authorization endpoint reachable". A rendezvous that
    //    reports NOT READY when the control plane blips is removed from the load
    //    balancer, which stops peers from exchanging candidates, which puts the
    //    control plane back in the critical path of every reconnect — exactly
    //    what `docs/protocol.md` §10.1 and I5 forbid. The policy makes the
    //    mistake unrepresentable: `readiness()` refuses any probe declaring
    //    `ProbeKind::ControlPlane`. The divergence is reported to the
    //    integration lead (README.md §8).
    // TLS before anything else that could serve: a key that cannot be loaded
    // must stop the process, not degrade it to a plaintext listener. There is no
    // code path in `service-common`'s builder that produces a plaintext or
    // client-auth-optional configuration, so "degrade" is not an option this
    // process has to decline — it is one it does not have.
    let server_tls = svc::tls::ServerTlsBuilder::from_pem_file(&rz_cfg.tls_key_path).build()?;
    let server_spki_len = server_tls.public_key().len();

    let shared = Arc::new(rz::server::Shared {
        router: tokio::sync::Mutex::new(rz::ingress::Router {
            attachments: rz::attach::AttachRegistry::new(rz_cfg.attach),
            mailboxes: rz::mailbox::MailboxStore::new(rz_cfg.mailbox),
            labels: rz::label::Labeller::default(),
        }),
        limiter: tokio::sync::Mutex::new(rz::admission::SourceLimiter::new(rz_cfg.admission)),
        // Derived-preferred, not merely channel-pinned: RZ-10. A device whose
        // TLS key derives to the `device_id` it claims takes that name back from
        // an impostor holding it, and a rotated device still binds.
        bindings: tokio::sync::Mutex::new(svc::binding::DerivedPreferred::new(rz_cfg.binding)),
        tls: tokio_rustls::TlsAcceptor::from(server_tls.config()),
        connections: Arc::new(tokio::sync::Semaphore::new(rz_cfg.max_connections)),
        config: rz_cfg.clone(),
        metrics: metrics.clone(),
    });

    let listener = tokio::net::TcpListener::bind(rz_cfg.listen_tcp).await?;
    let bound_addr = listener.local_addr()?;

    let probe_state = Arc::clone(&shared);
    let health =
        svc::health::HealthRegistry::builder(svc::health::ReadinessPolicy::NoControlPlaneCalls)
            .readiness(svc::health::FnProbe::new(
                "c4_listener",
                svc::health::ProbeKind::Local,
                move || {
                    let s = Arc::clone(&probe_state);
                    async move {
                        // Ready means "the routing tables are reachable and the
                        // ceilings hold". It asks nothing of any other process.
                        let router = s.router.lock().await;
                        if router.mailboxes.total_bytes() <= s.config.mailbox.max_total_bytes {
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

    // 4. Shutdown, wired to health so the drain turns /readyz red immediately.
    let shutdown = Arc::new(
        svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
            .with_health(health.clone()),
    );
    let handle = shutdown.handle();

    // 5. The admin listener on :9090.
    let admin = tokio::spawn(svc::admin::serve(
        cfg.admin_addr,
        svc::admin::router(health.clone(), metrics.clone()),
        {
            let h = handle.clone();
            async move { h.draining().await }
        },
    ));

    let sweeper = tokio::spawn(rz::server::sweeper(
        Arc::clone(&shared),
        handle.clone(),
        rz_cfg.sweep_interval,
    ));
    let serving = tokio::spawn(rz::server::serve(
        listener,
        Arc::clone(&shared),
        handle.clone(),
    ));

    tracing::info!(
        twinvpn.outcome = "listening",
        // The bound port is operational, not personal. No client address, no
        // device identifier, ever appears in a log line from this service.
        port = bound_addr.port(),
        // The server's own public key length, so an operator can see that RFC
        // 7250 mode came up. The key itself is printed by `--print-server-key`
        // rather than into every startup log line.
        server_key_bytes = server_spki_len,
        "rendezvous serving C4 ingress over TLS 1.3 with mutual raw public keys"
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
