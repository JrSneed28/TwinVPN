//! Component tests for `twinvpn_service_common::shutdown`.
//!
//! These drive tokio's virtual clock, so a 120 s drain is asserted in
//! microseconds and nothing here waits on wall time.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use twinvpn_service_common::health::ServiceState;
use twinvpn_service_common::metrics::Metrics;
use twinvpn_service_common::shutdown::*;

fn cfg(grace_ms: u64) -> ShutdownConfig {
    ShutdownConfig {
        grace: Duration::from_millis(grace_ms),
        drain_deadline: Duration::from_millis(120_000),
        teardown_step_timeout: Duration::from_millis(500),
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_actually_waits_for_in_flight_work() {
    let s = Arc::new(Shutdown::new(cfg(120_000), Metrics::new()));
    let h = s.handle();
    let done = Arc::new(AtomicUsize::new(0));

    let guard = h.try_acquire().expect("still admitting");
    let d = done.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5_000)).await;
        d.fetch_add(1, Ordering::SeqCst);
        drop(guard);
    });

    let report = s.shutdown().await;
    assert!(report.drained, "the drain must wait, not abandon");
    assert_eq!(report.outstanding, 0);
    assert_eq!(
        done.load(Ordering::SeqCst),
        1,
        "the in-flight operation must have completed"
    );
}

#[tokio::test(start_paused = true)]
async fn a_dropped_request_at_sigterm_would_be_visible() {
    // The control: work that never finishes. The grace period bounds it and
    // the expiry is reported rather than silent.
    let metrics = Metrics::new();
    let s = Shutdown::new(cfg(1_000), metrics.clone());
    let h = s.handle();
    let _guard = h.acquire_unconditionally();

    let report = s.shutdown().await;
    assert!(!report.drained);
    assert_eq!(report.outstanding, 1);
    assert!(metrics.render().contains(&format!(
        "{} 1",
        twinvpn_service_common::metrics::names::SHUTDOWN_GRACE_EXPIRED
    )));
    assert!(metrics.render().contains(&format!(
        "{} 1",
        twinvpn_service_common::metrics::names::SHUTDOWN_INFLIGHT_AT_DEADLINE
    )));
}

#[tokio::test(start_paused = true)]
async fn new_work_is_refused_once_draining() {
    let s = Arc::new(Shutdown::new(cfg(1_000), Metrics::new()));
    let h = s.handle();
    assert!(h.try_acquire().is_some());
    let s2 = s.clone();
    let jh = tokio::spawn(async move { s2.shutdown().await });
    // Give the drain a chance to flip the flag.
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(h.is_draining());
    assert!(
        h.try_acquire().is_none(),
        "a draining service must not admit new work"
    );
    // The unconditional acquire is still available for drain-internal work.
    drop(h.acquire_unconditionally());
    let _ = jh.await;
}

#[tokio::test(start_paused = true)]
async fn readiness_goes_red_the_instant_the_drain_begins() {
    use twinvpn_service_common::health::{
        FnProbe, HealthRegistry, ProbeKind, ProbeOutcome, ReadinessPolicy,
    };

    let health = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(FnProbe::new("x", ProbeKind::Local, || async {
            ProbeOutcome::Ready
        }))
        .unwrap()
        .cache_ttl(Duration::from_secs(3600))
        .build();
    health.set_state(ServiceState::Serving);
    assert!(health.readiness().await.status.is_ready());

    let s = Shutdown::new(cfg(10), Metrics::new()).with_health(health.clone());
    let _ = s.shutdown().await;
    assert!(!health.readiness().await.status.is_ready());
}

#[tokio::test(start_paused = true)]
async fn teardown_runs_in_ascending_order_after_the_drain() {
    let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let s = Shutdown::new(cfg(10), Metrics::new());

    for (o, name) in [(90u16, "otel"), (10, "db"), (50, "cache")] {
        let rec = order.clone();
        s.register_teardown(o, name, move || {
            let rec = rec.clone();
            futures_step::boxed(async move {
                rec.lock().expect("poisoned").push(name);
            })
        });
    }

    let report = s.shutdown().await;
    assert_eq!(
        *order.lock().unwrap(),
        vec!["db", "cache", "otel"],
        "the exporter must be last so it carries the drain's own records"
    );
    assert!(report.teardown.iter().all(|t| t.completed));
}

#[tokio::test(start_paused = true)]
async fn a_wedged_teardown_step_is_bounded_and_reported() {
    let s = Shutdown::new(cfg(10), Metrics::new());
    s.register_teardown(1, "wedged", || {
        futures_step::boxed(async { std::future::pending::<()>().await })
    });
    s.register_teardown(2, "after", || futures_step::boxed(async {}));

    let report = s.shutdown().await;
    assert_eq!(report.teardown[0].name, "wedged");
    assert!(!report.teardown[0].completed);
    assert!(
        report.teardown[1].completed,
        "a wedged step must not block the ones after it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_task_can_await_the_drain_signal() {
    let s = Arc::new(Shutdown::new(cfg(1_000), Metrics::new()));
    let h = s.handle();
    let observed = Arc::new(AtomicBool::new(false));
    let o = observed.clone();
    let watcher = tokio::spawn(async move {
        h.draining().await;
        o.store(true, Ordering::SeqCst);
    });
    let _ = s.shutdown().await;
    watcher.await.expect("the watcher task must complete");
    assert!(observed.load(Ordering::SeqCst));
}

#[test]
fn the_drain_deadline_default_is_adr_0002s_120_seconds() {
    let s = Shutdown::new(ShutdownConfig::default(), Metrics::new());
    assert_eq!(s.drain_deadline_ms(), 120_000);
}
