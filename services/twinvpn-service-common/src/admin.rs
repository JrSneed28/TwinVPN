//! The admin listener: `/healthz`, `/readyz`, `/metrics` on one port.
//!
//! **Authority:** `infra/README.md` §2.1 —
//!
//! > One listener per service on **:9090**, serving three paths — `/healthz`
//! > (liveness), `/readyz` (readiness), `/metrics` (Prometheus). One port to
//! > open, one port to firewall, one port to forget to publish. It is
//! > operator-facing and MUST NOT be exposed to an untrusted network.
//!
//! and §5 (the container `HEALTHCHECK` makes a **real HTTP request** to
//! `/readyz`, because "a listening socket proves a bind, not health"), and
//! `infra/prometheus/prometheus.yml` (job `twinvpn-services` scrapes
//! `:9090/metrics` directly).
//!
//! `build/verify/check-compose.py` fails the build if the Dockerfile's
//! healthcheck stops targeting `/readyz` or the liveness path disappears, so
//! these three paths are a contract with the infrastructure domain, not a
//! convention.
//!
//! # Status codes
//!
//! | Path | 200 | 503 |
//! |---|---|---|
//! | `/healthz` | every liveness invariant holds | the process is wedged; a restart would help |
//! | `/readyz` | serving **and** every dependency available | starting, draining, a dependency down, or **no probe registered** |
//! | `/metrics` | always | — |
//!
//! `/readyz` answering 503 while starting and while draining is deliberate: the
//! container `HEALTHCHECK` gates `depends_on: condition: service_healthy`, and a
//! service that reported ready before it could serve would let its dependents
//! start into a failure.

use std::net::SocketAddr;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::correlation::Correlation;
use crate::health::HealthRegistry;
use crate::metrics::{Labels, Metrics};

/// What the admin routes need.
#[derive(Debug, Clone)]
pub struct AdminState {
    /// Liveness and readiness.
    pub health: HealthRegistry,
    /// The metric registry rendered at `/metrics`.
    pub metrics: Metrics,
}

/// Builds the admin router.
///
/// A service may `merge` further operator-facing routes onto it, but MUST NOT
/// put a device-facing surface here: this listener is not published to an
/// untrusted network and nothing on it is authenticated.
pub fn router(health: HealthRegistry, metrics: Metrics) -> Router {
    // Register the two lifecycle gauges eagerly so `/metrics` reports `0`
    // rather than nothing before the first transition.
    metrics
        .gauge(
            crate::metrics::names::UP,
            "1 while the process is running",
            Labels::new(),
        )
        .set(1);
    let _registered = metrics.gauge(
        crate::metrics::names::READY,
        "1 when /readyz would return 200",
        Labels::new(),
    );
    let _registered = metrics.gauge(
        crate::metrics::names::DRAINING,
        "1 once a drain has begun",
        Labels::new(),
    );

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .with_state(AdminState { health, metrics })
}

async fn healthz(State(s): State<AdminState>) -> Response {
    let report = s.health.liveness();
    let status = if report.alive {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    json(status, report.to_json())
}

async fn readyz(State(s): State<AdminState>) -> Response {
    let started = std::time::Instant::now();
    let report = s.health.readiness().await;

    s.metrics
        .gauge(
            crate::metrics::names::READY,
            "1 when /readyz would return 200",
            Labels::new(),
        )
        .set(i64::from(report.status.is_ready()));
    s.metrics
        .gauge(
            crate::metrics::names::READINESS_DURATION_MS,
            "duration of the most recent readiness evaluation",
            Labels::new(),
        )
        .set(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX));

    for check in &report.checks {
        if let Some(code) = check.reason_code {
            s.metrics
                .counter(
                    crate::metrics::names::READINESS_FAILURES,
                    "readiness probe failures by reason_code",
                    Labels::new().with(crate::metrics::Label::ReasonCode, code.as_str()),
                )
                .inc();
        }
    }

    let status = if report.status.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    json(status, report.to_json())
}

async fn metrics_handler(State(s): State<AdminState>) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        s.metrics.render(),
    )
        .into_response()
}

fn json(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// Serves `router` on `addr` until `shutdown` resolves.
///
/// The listener is closed as soon as the drain begins, so a load balancer's next
/// health check fails fast rather than waiting for a timeout.
///
/// # Errors
///
/// Any bind or accept error. A service that cannot bind its admin listener has
/// no readiness endpoint, and `infra/README.md` §5 makes `/readyz` the gate every
/// dependent waits on — so this is fatal at startup rather than a warning.
pub async fn serve<F>(addr: SocketAddr, router: Router, shutdown: F) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

/// Binds the admin listener and reports the bound address.
///
/// For a test or a deployment that asks for port 0.
///
/// # Errors
///
/// Any bind error.
pub async fn bind(addr: SocketAddr) -> std::io::Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    Ok((listener, bound))
}

/// Axum middleware that carries `correlation_id` and `causation_id` across an
/// HTTP hop.
///
/// Extracts them from the request headers, binds them as the ambient
/// [`Correlation`] for the handler, records them on a span so every event inside
/// inherits them, and echoes them on the response.
///
/// This is the mechanism `ownership.md` §6 rule 6 needs: a handler cannot drop
/// the ids by forgetting to pass them, because it never holds them.
pub async fn correlation_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let correlation = Correlation::from_headers(|name| {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(std::borrow::ToOwned::to_owned)
    });

    let span = crate::correlation::request_span("http", &correlation);
    let _entered = span.enter();

    let mut response = crate::correlation::scope(correlation, next.run(request)).await;

    for (name, value) in correlation.to_headers() {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(n, v);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{
        FnLiveness, FnProbe, HealthRegistry, ProbeKind, ProbeOutcome, ReadinessPolicy, ServiceState,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A minimal HTTP/1.1 client: the crate must not acquire an HTTP client
    /// dependency just to test its own listener.
    async fn get_path(base: &str, path: &str) -> (StatusCode, String) {
        let mut s = tokio::net::TcpStream::connect(base).await.expect("connect");
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
        (StatusCode::from_u16(code).expect("status"), body)
    }

    #[tokio::test]
    async fn the_three_paths_exist_and_readyz_reflects_a_dependency() {
        let up = Arc::new(AtomicBool::new(true));
        let probe_up = up.clone();
        let health = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
            .readiness(FnProbe::new("postgres", ProbeKind::Datastore, move || {
                let up = probe_up.clone();
                async move {
                    if up.load(Ordering::Relaxed) {
                        ProbeOutcome::Ready
                    } else {
                        ProbeOutcome::NotReady(twinvpn_types::codes::CONTROL_UNREACHABLE)
                    }
                }
            }))
            .unwrap()
            .liveness(FnLiveness::new("event_loop", || true))
            .cache_ttl(Duration::ZERO)
            .build();
        health.set_state(ServiceState::Serving);

        let metrics = Metrics::new();
        let (listener, addr) = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let app = router(health.clone(), metrics.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = addr.to_string();

        let (code, body) = get_path(&base, "/healthz").await;
        assert_eq!(code, StatusCode::OK);
        assert!(body.contains("alive"), "{body}");

        let (code, _) = get_path(&base, "/readyz").await;
        assert_eq!(code, StatusCode::OK);

        // The dependency dies. /readyz must go red — a 200 here would convert an
        // outage into a silent one.
        up.store(false, Ordering::Relaxed);
        let (code, body) = get_path(&base, "/readyz").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("CONTROL.UNREACHABLE"), "{body}");

        // ...while /healthz stays green: a restart would not help.
        let (code, _) = get_path(&base, "/healthz").await;
        assert_eq!(code, StatusCode::OK);

        let (code, body) = get_path(&base, "/metrics").await;
        assert_eq!(code, StatusCode::OK);
        assert!(body.contains("twinvpn_service_up 1"), "{body}");
        assert!(body.contains("twinvpn_service_ready 0"), "{body}");
        assert!(
            body.contains(
                "twinvpn_readiness_probe_failures_total{reason_code=\"CONTROL.UNREACHABLE\"}"
            ),
            "{body}"
        );
    }

    #[tokio::test]
    async fn readyz_is_red_while_starting_and_while_draining() {
        let health = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
            .readiness(FnProbe::new("x", ProbeKind::Local, || async {
                ProbeOutcome::Ready
            }))
            .unwrap()
            .cache_ttl(Duration::ZERO)
            .build();
        let metrics = Metrics::new();
        let (listener, addr) = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let app = router(health.clone(), metrics);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base = addr.to_string();

        // Starting.
        let (code, body) = get_path(&base, "/readyz").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("starting"), "{body}");

        health.set_state(crate::health::ServiceState::Serving);
        assert_eq!(get_path(&base, "/readyz").await.0, StatusCode::OK);

        health.set_state(crate::health::ServiceState::Draining);
        let (code, body) = get_path(&base, "/readyz").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("draining"), "{body}");
    }

    #[tokio::test]
    async fn correlation_survives_an_http_round_trip_through_the_middleware() {
        async fn echo() -> String {
            // The handler never touches a header; it reads the ambient value.
            let c = crate::correlation::current();
            c.correlation_id()
                .map(|v| twinvpn_types::Identifier::to_hex(&v))
                .unwrap_or_default()
        }

        let app: Router = Router::new()
            .route("/echo", get(echo))
            .layer(axum::middleware::from_fn(correlation_middleware));

        let (listener, addr) = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let hex = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
        let req = format!(
            "GET /echo HTTP/1.1\r\nHost: t\r\n{}: {hex}\r\nConnection: close\r\n\r\n",
            crate::correlation::HEADER_CORRELATION_ID
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();

        // The handler saw it...
        assert!(text.ends_with(hex), "{text}");
        // ...and the response echoes it, so the next hop inherits it.
        assert!(
            text.to_ascii_lowercase()
                .contains(crate::correlation::HEADER_CORRELATION_ID),
            "{text}"
        );
    }
}
