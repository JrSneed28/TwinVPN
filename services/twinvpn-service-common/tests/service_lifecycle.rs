//! One component test that wires the pieces together the way a service does.
//!
//! Config → metrics → health → admin listener → shutdown, then a drain, with a
//! real HTTP request to `/readyz` at each stage — because that is what the
//! container `HEALTHCHECK` does (`infra/README.md` §5), and a readiness endpoint
//! exercised only through a Rust function call is a readiness endpoint whose
//! wire behaviour has never been observed.
//!
//! The observability stack is deliberately **not** initialised here: installing a
//! subscriber is a process-global side effect and this binary runs several tests
//! concurrently. `tests/obs_redaction.rs` covers the layer with a scoped
//! subscriber instead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use twinvpn_service_common::config::{keys, MapEnv, RegistryCheck, ServiceConfig};
use twinvpn_service_common::health::{
    FnLiveness, FnProbe, HealthRegistry, ProbeKind, ProbeOutcome, ReadinessPolicy, ServiceState,
};
use twinvpn_service_common::metrics::Metrics;
use twinvpn_service_common::shutdown::{futures_step, Shutdown};

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.expect("read");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .expect("status line");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (code, body)
}

#[tokio::test]
async fn a_service_starts_serves_drains_and_stops() {
    // 1. Configuration, from an explicit map rather than the process
    //    environment, so this test does not race any other.
    let env = MapEnv::new()
        .with(keys::SERVICE_NAME, "control-plane")
        .with(keys::ENVIRONMENT, "test")
        .with(keys::ADMIN_ADDR, "127.0.0.1:0")
        .with(keys::SHUTDOWN_GRACE_MS, "2000")
        .with(keys::OTEL_ENABLED, "false");
    let cfg = ServiceConfig::load(
        &env,
        "control-plane",
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_COORDINATION_SERVICE",
        RegistryCheck::Skip,
    )
    .expect("configuration loads");
    assert_eq!(cfg.shutdown_grace, Duration::from_millis(2000));

    let metrics = Metrics::new();

    // 2. Health: one liveness invariant, one dependency.
    let db_up = Arc::new(AtomicBool::new(true));
    let probe_flag = db_up.clone();
    let health = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(FnProbe::new("postgres", ProbeKind::Datastore, move || {
            let up = probe_flag.clone();
            async move {
                if up.load(Ordering::Relaxed) {
                    ProbeOutcome::Ready
                } else {
                    ProbeOutcome::NotReady(twinvpn_service_common::codes::CONTROL_UNREACHABLE)
                }
            }
        }))
        .expect("a control plane may probe its datastore")
        .liveness(FnLiveness::new("event_loop", || true))
        .cache_ttl(Duration::ZERO)
        .build();

    // 3. Shutdown, wired to health so /readyz goes red the instant a drain starts.
    let shutdown =
        Arc::new(Shutdown::new(cfg.shutdown_config(), metrics.clone()).with_health(health.clone()));
    let handle = shutdown.handle();

    let torn_down = Arc::new(AtomicBool::new(false));
    let td = torn_down.clone();
    shutdown.register_teardown(10, "db_pool", move || {
        let td = td.clone();
        futures_step::boxed(async move {
            td.store(true, Ordering::SeqCst);
        })
    });

    // 4. The admin listener.
    let (listener, addr) = twinvpn_service_common::admin::bind(cfg.admin_addr)
        .await
        .expect("bind");
    let app = twinvpn_service_common::admin::router(health.clone(), metrics.clone());
    let serve_handle = handle.clone();
    let server = tokio::spawn(async move {
        let _ = axum_serve(listener, app, async move { serve_handle.draining().await }).await;
    });

    // Starting: not ready. A dependent must not start into a failure.
    let (code, body) = http_get(addr, "/readyz").await;
    assert_eq!(code, 503);
    assert!(body.contains("starting"), "{body}");

    // 5. Serving.
    health.set_state(ServiceState::Serving);
    assert_eq!(http_get(addr, "/readyz").await.0, 200);
    assert_eq!(http_get(addr, "/healthz").await.0, 200);

    // A request is in flight while the drain begins.
    let guard = handle.try_acquire().expect("still admitting");

    // 6. The dependency dies: live, not ready.
    db_up.store(false, Ordering::Relaxed);
    let (code, body) = http_get(addr, "/readyz").await;
    assert_eq!(code, 503, "an unreachable dependency must go red");
    assert!(body.contains("CONTROL.UNREACHABLE"), "{body}");
    assert_eq!(
        http_get(addr, "/healthz").await.0,
        200,
        "a restart would not help, so liveness stays green"
    );
    db_up.store(true, Ordering::Relaxed);
    assert_eq!(http_get(addr, "/readyz").await.0, 200);

    // 7. Drain. The in-flight guard is released a moment later; the shutdown
    //    must wait for it rather than abandon it.
    let released = Arc::new(AtomicBool::new(false));
    let r = released.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        r.store(true, Ordering::SeqCst);
        drop(guard);
    });

    let report = shutdown.shutdown().await;
    assert!(report.drained, "the drain must wait for in-flight work");
    assert!(released.load(Ordering::SeqCst));
    assert_eq!(report.outstanding, 0);
    assert_eq!(report.teardown.len(), 1);
    assert!(report.teardown[0].completed);
    assert!(torn_down.load(Ordering::SeqCst), "teardown must have run");

    // The listener stops on the drain signal.
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    // 8. The metrics tell the operator what happened, with only §9 labels.
    let rendered = metrics.render();
    assert!(rendered.contains("twinvpn_service_up 1"), "{rendered}");
    assert!(
        rendered.contains("twinvpn_service_draining 1"),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "twinvpn_readiness_probe_failures_total{reason_code=\"CONTROL.UNREACHABLE\"} 1"
        ),
        "{rendered}"
    );
    assert!(
        !rendered.contains("twinvpn_shutdown_grace_expired_total 1"),
        "a clean drain must not report an expiry: {rendered}"
    );
    for forbidden in ["session_id", "device_id", "twinnet_id", "endpoint"] {
        assert!(
            !rendered.contains(forbidden),
            "{forbidden} must never appear as a metric label (ADR-0015 §9, O-13)"
        );
    }
}

async fn axum_serve<F>(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

#[tokio::test]
async fn a_relay_shaped_service_is_ready_with_no_control_plane_reachable() {
    // I5, end to end: a relay's readiness is local-only, so it comes up and
    // stays up with the whole control plane down. ADR-0005 §11.3 verifies the
    // RelayCapabilityToken offline against a signed issuer key set.
    let issuer_keys_loaded = Arc::new(AtomicBool::new(true));
    let carriages_bound = Arc::new(AtomicBool::new(true));

    let a = issuer_keys_loaded.clone();
    let b = carriages_bound.clone();
    let health = HealthRegistry::builder(ReadinessPolicy::NoControlPlaneCalls)
        .readiness(FnProbe::new("issuer_keys", ProbeKind::Local, move || {
            let a = a.clone();
            async move {
                if a.load(Ordering::Relaxed) {
                    ProbeOutcome::Ready
                } else {
                    ProbeOutcome::NotReady(twinvpn_service_common::codes::AUTH_KEY_UNAVAILABLE)
                }
            }
        }))
        .expect("local")
        .readiness(FnProbe::new(
            "carriages_bound",
            ProbeKind::Local,
            move || {
                let b = b.clone();
                async move {
                    if b.load(Ordering::Relaxed) {
                        ProbeOutcome::Ready
                    } else {
                        ProbeOutcome::NotReady(twinvpn_service_common::codes::NET_IFACE_DOWN)
                    }
                }
            },
        ))
        .expect("local")
        .cache_ttl(Duration::ZERO)
        .build();
    health.set_state(ServiceState::Serving);

    assert!(health.readiness().await.status.is_ready());

    // The bootstrap stub is an EMPTY issuer key set on purpose, so no token
    // verifies (`infra/README.md` §4.6). That must be visible as not-ready.
    issuer_keys_loaded.store(false, Ordering::Relaxed);
    let r = health.readiness().await;
    assert!(!r.status.is_ready());
    assert_eq!(
        r.checks
            .iter()
            .find(|c| c.name == "issuer_keys")
            .and_then(|c| c.reason_code),
        Some(twinvpn_service_common::codes::AUTH_KEY_UNAVAILABLE)
    );

    // And every probe on this registry is local: no probe reaches the control
    // plane, by construction rather than by review.
    assert!(r.checks.iter().all(|c| c.kind == ProbeKind::Local));
}
