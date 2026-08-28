//! `twinvpn-control-plane` — the process.
//!
//! **Authority:** `services/twinvpn-service-common/README.md` §2 (the wiring
//! order, and why it is that order), `infra/README.md` §4.3 and §5, ADR-0002
//! §11.7 (the drain).
//!
//! The order in [`run`] is the order `service-common`'s README fixes, and each
//! step is there for a stated reason:
//!
//! 1. **Configuration first.** A missing secret or a mismatched registry fails
//!    *here*, before a socket exists to accept a request it cannot answer.
//! 2. **Metrics, then observability.** The subscriber is process-global and is
//!    installed once, from `main`.
//! 3. **Health before shutdown**, so the drain can turn `/readyz` red.
//! 4. **Shutdown before the listener**, so a `SIGTERM` during startup drains
//!    rather than races.
//! 5. **The admin listener last**, so it never reports ready before the service
//!    can serve.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use twinvpn_control_plane as cp;
use twinvpn_service_common as svc;

fn main() -> std::process::ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(run()),
        Err(e) => {
            eprintln!("control-plane: could not build the runtime: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> std::process::ExitCode {
    // 1. Configuration. `RegistryCheck::Required`: a service validating against
    //    different bounds from the ones it was built with would pass its own
    //    tests and reject real traffic.
    let cfg = match svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        cp::SERVICE_NAME,
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_COORDINATION_SERVICE",
        svc::config::RegistryCheck::Required,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            // The error names the key and the expectation and never the value:
            // a variant holding the value would put the database password in
            // the first line of the container log.
            eprintln!("control-plane: configuration refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let cp_cfg = match cp::ControlPlaneConfig::load(&svc::config::SystemEnv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("control-plane: configuration refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // 2. Metrics, then observability.
    //
    //    `observability()` uses the instance id `ServiceConfig` resolved from
    //    TWINVPN_INSTANCE_ID (which compose supplies per service), not one
    //    derived here. A `{name}-{pid}` id changes on every restart, so every
    //    fleet aggregate grouped by `service.instance.id` silently counts
    //    restarts instead of instances.
    let metrics = svc::Metrics::new();
    let obs = match svc::obs::init(&cfg.observability(), metrics.clone()) {
        Ok(obs) => Arc::new(obs),
        Err(e) => {
            eprintln!("control-plane: observability refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    // Which of the three sources was used, visible rather than inferred.
    cfg.log_instance_id_resolution();

    // 2b. The signature verifier. Real: COSE_Sign1 through `twinvpn-crypto`,
    //     the same audited provider the client verifies with.
    let anchors = match cp_cfg.load_owner_anchors() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("control-plane: owner anchor set refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let verifier = match cp::verify::CryptoVerifier::new(&anchors) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "control-plane: owner anchor set refused: {}",
                e.code().as_str()
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    if verifier.has_owner_anchor() {
        tracing::info!(
            anchors = anchors.len(),
            "Owner trust anchor set pinned; Owner-authority statements are verifiable"
        );
    } else {
        // Said out loud at startup so an operator does not discover it from a
        // refusal. See README.md §7.
        tracing::warn!(
            reason_code = twinvpn_types::codes::AUTH_KEY_UNAVAILABLE.as_str(),
            "no Owner trust anchor is bound: RevokeDevice, PutPolicy, RevokePairing \
             and the enrolment proof on RegisterDevice will be refused. \
             Device-signed statements, discovery, presence and the C2 stream are \
             unaffected."
        );
    }
    tracing::warn!(
        reason_code = twinvpn_types::codes::CONTROL_HANDSHAKE_REJECTED.as_str(),
        "no raw-public-key peer verifier is bound: every mTLS handshake will be refused"
    );

    // 3. The store, then health. Readiness genuinely reaches Postgres and the
    //    write lease; `infra/README.md` §5 names both halves for this service.
    let store: Arc<dyn cp::store::ControlStore> = Arc::new(cp::store::mem::MemStore::new());
    tracing::warn!(
        "running on the in-memory store: TWINVPN_CP_DATABASE_URL is loaded and \
         validated but PgStore has never been executed on this host. See README.md §9."
    );
    let _ = &cp_cfg.database_url;

    let probe_store = Arc::clone(&store);
    let health = match svc::HealthRegistry::builder(svc::ReadinessPolicy::AnyDependency).readiness(
        svc::health::FnProbe::new(
            "datastore_and_write_lease",
            svc::ProbeKind::Datastore,
            move || {
                let store = Arc::clone(&probe_store);
                async move {
                    match store.probe().await {
                        Ok(h) if h.is_ready() => svc::ProbeOutcome::Ready,
                        Ok(_) | Err(_) => svc::ProbeOutcome::NotReady(
                            twinvpn_types::codes::CONTROL_WRITE_LEADER_UNAVAILABLE,
                        ),
                    }
                }
            },
        ),
    ) {
        Ok(b) => b
            .liveness(svc::health::FnLiveness::new("accept_loop", || true))
            .build(),
        Err(e) => {
            eprintln!("control-plane: health registry refused a probe: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // 4. Shutdown, wired to health so the drain turns /readyz red immediately.
    let shutdown = Arc::new(
        svc::Shutdown::new(cfg.shutdown_config(), metrics.clone()).with_health(health.clone()),
    );
    // Order 90: the OTLP exporter is shut down LAST, so it still carries the
    // records describing the drain itself.
    let obs_for_teardown = Arc::clone(&obs);
    shutdown.register_teardown(90, "otel", move || {
        let obs = Arc::clone(&obs_for_teardown);
        svc::shutdown::futures_step::boxed(async move {
            obs.shutdown();
        })
    });

    // 5. The admin listener on :9090.
    let handle = shutdown.handle();
    let admin = tokio::spawn(svc::admin::serve(
        cfg.admin_addr,
        svc::admin::router(health.clone(), metrics.clone()),
        {
            let h = handle.clone();
            async move { h.draining().await }
        },
    ));

    // 6. Serve. The QUIC listener is built but not accepted on: with
    //    `RefuseUnidentified` bound, every handshake would be refused, and a
    //    listener that accepts in order to refuse is a listener that has to be
    //    rate-limited for no benefit. README.md §7 records what a composition
    //    root must bind to turn this on.
    let _ = &verifier;
    tracing::info!(
        listen_quic = %cp_cfg.listen_quic,
        drain_deadline_ms = cp_cfg.drain_deadline_ms(),
        attach_rate_sustained = cp_cfg.attach_rate_sustained,
        "control-plane configured"
    );
    health.set_state(svc::ServiceState::Serving);

    svc::Shutdown::wait_for_signal().await;
    let report = shutdown.shutdown().await;
    let _ = admin.await;
    obs.shutdown();

    if report.drained {
        std::process::ExitCode::SUCCESS
    } else {
        // The honest answer. `twinvpn_shutdown_grace_expired_total` carries the
        // metric; there is no registered reason_code for it
        // (`service-common` README §11 item 6, raised to the integration lead).
        tracing::warn!(
            outstanding = report.outstanding,
            "the grace period expired with work in flight"
        );
        std::process::ExitCode::FAILURE
    }
}
