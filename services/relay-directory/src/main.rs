//! `twinvpn-relay-directory` — process entry point.
//!
//! Wiring order is `twinvpn-service-common`'s README §2. The readiness set is
//! `infra/README.md` §5's for this service: *Postgres reachable; signing key
//! loaded; the current map satisfies ≥2 alternates / ≥2 failure domains.*
//!
//! The third probe is the interesting one. A relay-directory that is serving a
//! map which breaches ADR-0006 §11.1 rule 3's floor is a directory handing every
//! device a candidate set that cannot survive one failure — so it reports **not
//! ready** rather than serving quietly, which is what makes the floor an
//! operational fact and not only a publication-time check.
#![forbid(unsafe_code)]

use std::sync::{Arc, RwLock};

use twinvpn_relay_directory::api::{router, MapCache, SharedCache};
use twinvpn_relay_directory::config::DirectoryConfig;
use twinvpn_relay_directory::fleet::{FleetStore, InMemoryFleet};
use twinvpn_relay_directory::sign::{MapSigner, SigningKey, Unsigned};
use twinvpn_service_common as svc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        "relay-directory",
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_RELAY_SELECTION",
        svc::config::RegistryCheck::Required,
    )?;
    let dir_cfg = DirectoryConfig::load(&svc::config::SystemEnv)?;

    // The resolved `TWINVPN_INSTANCE_ID`, not the operator group: a group is
    // shared by every instance in the fleet, so using it as `service.instance.id`
    // made every relay-directory look like one instance.
    let metrics = svc::metrics::Metrics::new();
    let obs = svc::obs::init(&cfg.observability(), metrics.clone())?;
    cfg.log_instance_id_resolution();

    // The signing key is read so a missing one fails at startup rather than at
    // the first publish. The SIGNER is still the fail-closed default until a
    // COSE_Sign1/Ed25519 provider is installed — see README.md §7.
    let signing_key = SigningKey::load(&dir_cfg.map_signing_key_path);
    let signer: Box<dyn MapSigner> = Box::new(Unsigned);
    if signing_key.is_err() {
        tracing::error!(
            outcome = "unsigned",
            "map signing key is unreadable; no RelayMap can be published"
        );
    }
    let signer_installed = signer.key_id().is_empty().eq(&false);

    // S-09's registry. The Postgres binding is deferred; see README.md §8.
    let fleet: Arc<RwLock<InMemoryFleet>> = Arc::new(RwLock::new(InMemoryFleet::new()));
    let cache: SharedCache = Arc::new(RwLock::new(MapCache::new()));

    // --- readiness, infra/README.md §5 -------------------------------------
    let signer_probe = svc::health::FnProbe::new(
        "map_signing_key",
        svc::health::ProbeKind::Local,
        move || async move {
            if signer_installed {
                svc::health::ProbeOutcome::Ready
            } else {
                // Not ready, deliberately: an unsigned map is never published, so
                // a directory with no signer serves nothing new. Devices with a
                // cached map are unaffected (§11.1 rule 4).
                svc::health::ProbeOutcome::NotReady(twinvpn_types::codes::RELAY_MAP_UNVERIFIED)
            }
        },
    );

    let floor_probe = {
        let fleet = Arc::clone(&fleet);
        let floor = dir_cfg.floor;
        let group = dir_cfg.operator_group_id.clone();
        svc::health::FnProbe::new(
            "alternates_floor",
            svc::health::ProbeKind::Local,
            move || {
                let ok = fleet
                    .read()
                    .ok()
                    .is_some_and(|f| floor.check(&f.all(&group)).is_ok());
                async move {
                    if ok {
                        svc::health::ProbeOutcome::Ready
                    } else {
                        svc::health::ProbeOutcome::NotReady(
                            twinvpn_types::codes::RELAY_REGION_UNAVAILABLE,
                        )
                    }
                }
            },
        )
    };

    let health = svc::health::HealthRegistry::builder(svc::health::ReadinessPolicy::AnyDependency)
        .readiness(signer_probe)?
        .readiness(floor_probe)?
        .liveness(svc::health::FnLiveness::new("publisher", || true))
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

    // The device-facing surface: one route, no per-connection input.
    let device_api = tokio::spawn({
        let app = router(Arc::clone(&cache));
        let addr = dir_cfg.listen_tcp;
        let h = handle.clone();
        async move {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(async move { h.draining().await })
                        .await;
                }
                Err(e) => tracing::error!(
                    outcome = "bind_failed",
                    error.type = "io",
                    "cannot bind the relay-map listener: {e}"
                ),
            }
        }
    });

    health.set_state(svc::health::ServiceState::Serving);
    tracing::info!(
        outcome = "serving",
        "relay-directory for operator group {} on {}",
        dir_cfg.operator_group_id,
        dir_cfg.listen_tcp
    );

    svc::shutdown::Shutdown::wait_for_signal().await;
    let _report = shutdown.shutdown().await;
    let _ = admin.await;
    let _ = device_api.await;
    obs.shutdown();
    Ok(())
}
