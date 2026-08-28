//! Component tests for `twinvpn_service_common::health`.
//!
//! The two that matter most are `readyz_goes_red_when_a_dependency_dies` and
//! `a_relay_cannot_register_a_control_plane_probe` (I5).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use twinvpn_service_common::health::*;
use twinvpn_types::codes;

fn flag_probe(name: &'static str, kind: ProbeKind, up: Arc<AtomicBool>) -> impl DependencyProbe {
    FnProbe::new(name, kind, move || {
        let up = up.clone();
        async move {
            if up.load(Ordering::Relaxed) {
                ProbeOutcome::Ready
            } else {
                ProbeOutcome::NotReady(codes::CONTROL_UNREACHABLE)
            }
        }
    })
}

#[tokio::test]
async fn readyz_goes_red_when_a_dependency_dies() {
    let up = Arc::new(AtomicBool::new(true));
    let h = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(flag_probe("postgres", ProbeKind::Datastore, up.clone()))
        .unwrap()
        .cache_ttl(Duration::ZERO)
        .build();
    h.set_state(ServiceState::Serving);

    assert_eq!(h.readiness().await.status, ReadinessStatus::Ready);

    up.store(false, Ordering::Relaxed);
    let r = h.readiness().await;
    assert_eq!(r.status, ReadinessStatus::NotReady);
    assert_eq!(r.checks[0].reason_code, Some(codes::CONTROL_UNREACHABLE));

    // ...and back again, because readiness is not latching.
    up.store(true, Ordering::Relaxed);
    assert_eq!(h.readiness().await.status, ReadinessStatus::Ready);
}

#[tokio::test]
async fn liveness_stays_green_while_a_dependency_is_down() {
    // The distinction that matters: a control plane whose database is
    // unreachable is LIVE and NOT READY. Restarting it would not help.
    let up = Arc::new(AtomicBool::new(false));
    let h = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(flag_probe("postgres", ProbeKind::Datastore, up))
        .unwrap()
        .liveness(FnLiveness::new("event_loop", || true))
        .cache_ttl(Duration::ZERO)
        .build();
    h.set_state(ServiceState::Serving);

    assert!(h.liveness().alive);
    assert!(!h.readiness().await.status.is_ready());
}

#[tokio::test]
async fn a_registry_with_no_probe_is_not_ready() {
    let h = HealthRegistry::builder(ReadinessPolicy::AnyDependency).build();
    h.set_state(ServiceState::Serving);
    assert_eq!(h.readiness().await.status, ReadinessStatus::NoProbes);
    assert!(!h.readiness().await.status.is_ready());
}

#[test]
fn a_relay_cannot_register_a_control_plane_probe() {
    let e = HealthRegistry::builder(ReadinessPolicy::NoControlPlaneCalls)
        .readiness(FnProbe::new(
            "control_plane_authz",
            ProbeKind::ControlPlane,
            || async { ProbeOutcome::Ready },
        ))
        .expect_err("I5 forbids this");
    assert_eq!(
        e,
        HealthError::ControlPlaneProbeForbidden {
            probe: "control_plane_authz"
        }
    );
}

#[test]
fn a_relay_can_register_its_own_local_probes() {
    let b = HealthRegistry::builder(ReadinessPolicy::NoControlPlaneCalls)
        .readiness(FnProbe::new("issuer_keys", ProbeKind::Local, || async {
            ProbeOutcome::Ready
        }))
        .expect("local probes are fine")
        .readiness(FnProbe::new(
            "carriages_bound",
            ProbeKind::Local,
            || async { ProbeOutcome::Ready },
        ))
        .expect("local probes are fine");
    assert_eq!(b.build().probe_count(), 2);
}

#[tokio::test]
async fn a_rendezvous_may_probe_the_control_plane() {
    // ADR-0002 §11.5 / infra/README.md §5: rendezvous depends on the control
    // plane for authorization, so its readiness legitimately checks it.
    let h = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(FnProbe::new(
            "cp_authz",
            ProbeKind::ControlPlane,
            || async { ProbeOutcome::Ready },
        ))
        .expect("permitted for the control plane's own clients")
        .cache_ttl(Duration::ZERO)
        .build();
    h.set_state(ServiceState::Serving);
    assert_eq!(h.readiness().await.status, ReadinessStatus::Ready);
}

#[tokio::test(start_paused = true)]
async fn a_hanging_probe_is_not_ready_rather_than_hanging_readyz() {
    let h = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(FnProbe::new("wedged", ProbeKind::Datastore, || async {
            std::future::pending::<ProbeOutcome>().await
        }))
        .unwrap()
        .probe_timeout(Duration::from_millis(50))
        .cache_ttl(Duration::ZERO)
        .build();
    h.set_state(ServiceState::Serving);
    let r = h.readiness().await;
    assert_eq!(r.status, ReadinessStatus::NotReady);
}

#[tokio::test]
async fn draining_is_immediately_not_ready() {
    let h = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(FnProbe::new("x", ProbeKind::Local, || async {
            ProbeOutcome::Ready
        }))
        .unwrap()
        .cache_ttl(Duration::from_secs(3600))
        .build();
    h.set_state(ServiceState::Serving);
    assert!(h.readiness().await.status.is_ready());
    h.set_state(ServiceState::Draining);
    // The long cache TTL must not keep a draining service green.
    assert_eq!(h.readiness().await.status, ReadinessStatus::Draining);
}

#[tokio::test]
async fn the_body_names_codes_and_never_a_connection_string() {
    let h = HealthRegistry::builder(ReadinessPolicy::AnyDependency)
        .readiness(FnProbe::new("postgres", ProbeKind::Datastore, || async {
            ProbeOutcome::NotReady(codes::CONTROL_UNREACHABLE)
        }))
        .unwrap()
        .cache_ttl(Duration::ZERO)
        .build();
    h.set_state(ServiceState::Serving);
    let body = h.readiness().await.to_json();
    assert!(body.contains("CONTROL.UNREACHABLE"), "{body}");
    assert!(body.contains("postgres"));
    assert!(!body.contains("password"));
    assert!(!body.contains("://"));
}
