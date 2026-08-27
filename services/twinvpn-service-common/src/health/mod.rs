//! Liveness and readiness — two different checks, both required.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 4,
//! `infra/README.md` §5, ADR-0005 §11.3 / architecture.md A-12 / I5 (a relay's
//! readiness must never make a control-plane call).
//!
//! | Path | Question | Fails when |
//! |---|---|---|
//! | `/healthz` | *Is this process running and are its own invariants holding?* | the process is wedged; a restart would help |
//! | `/readyz` | *Can this process serve — **including its dependencies**?* | a dependency is unreachable; a restart would **not** help |
//!
//! `infra/README.md` §5 is blunt about the failure mode this module exists to
//! prevent: "A readiness probe that returns 200 unconditionally is not a
//! readiness probe". A [`HealthRegistry`] with no readiness probe reports
//! [`ReadinessStatus::NoProbes`] and `/readyz` answers 503, so the unconfigured
//! case is red rather than green.
//!
//! # I5, made structural rather than remembered
//!
//! [`ReadinessPolicy::NoControlPlaneCalls`] exists for **two different reasons**,
//! and a reader who knows only the first will wrongly conclude the rule does not
//! apply to them.
//!
//! **The data plane: a relay must not need coordination to start.** ADR-0005
//! §11.3: relay admission verifies an Owner-rooted `RelayCapabilityToken`
//! **offline**, so a relay must come up and stay up with the whole control plane
//! down. `infra/README.md` §2.3 records that the compose topology has no
//! `depends_on` edge from a relay onto the control plane and that "that absence
//! is load-bearing".
//!
//! **The signalling path: a readiness check is itself a dependency.** A
//! rendezvous or presence instance that reports NOT READY on a control-plane
//! blip is pulled from the load balancer; that stops candidate exchange; and that
//! puts the control plane back in the critical path of every reconnect. **I5 is
//! violated by way of a health check, with no line of code anywhere calling the
//! control plane.** `rendezvous-connectivity` reached this independently and
//! diverged from `infra/README.md` §5 to get it, which is the right call.
//!
//! Either way the absence has to hold inside the process. Every probe declares a
//! [`ProbeKind`]; a registry built with [`ReadinessPolicy::NoControlPlaneCalls`]
//! **refuses to register** a `ControlPlane` probe. The dependency cannot be
//! acquired by accident, and the refusal is a wiring-time error rather than an
//! outage discovered when the control plane is down — the mistake is
//! unrepresentable, not merely discouraged.

mod probes;

pub use probes::{
    DependencyProbe, FnLiveness, FnProbe, LivenessCheck, ProbeFuture, ProbeKind, ProbeOutcome,
};

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use twinvpn_types::{codes, ReasonCode};

/// Whether the registry admits a control-plane probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessPolicy {
    /// Any probe, including a control-plane one.
    ///
    /// Correct for the control plane itself and for `relay-directory` and
    /// `relay-health`, whose readiness is a datastore.
    AnyDependency,
    /// **A control-plane probe is refused.** Chosen by the relays *and* by the
    /// rendezvous and presence, for two different and equally load-bearing
    /// reasons — see the module docs:
    ///
    /// * a **relay** that cannot become ready without coordination puts the
    ///   control plane in the data path (ADR-0005 §11.3);
    /// * a **rendezvous or presence** instance that goes NOT READY on a
    ///   control-plane blip is pulled from the load balancer, which stops
    ///   candidate exchange, which puts the control plane back in the reconnect
    ///   path — I5 violated by way of a health check.
    ///
    /// If you are wiring a service that talks to the control plane at all, the
    /// question is not "do I call it?" but "does my readiness *answer* depend on
    /// it?". If it does, this is the policy you want.
    NoControlPlaneCalls,
}

/// Why a probe could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HealthError {
    /// A `ControlPlane` probe on a `NoControlPlaneCalls` registry.
    #[error(
        "probe {probe} declares ProbeKind::ControlPlane, which this service forbids: \
         readiness must not depend on the control plane, either because the service \
         must start without coordination (ADR-0005 §11.3) or because going NOT READY \
         on a control-plane blip would pull it from the load balancer and put the \
         control plane back in the reconnect path (I5)"
    )]
    ControlPlaneProbeForbidden {
        /// The probe's static name.
        probe: &'static str,
    },
}

/// The lifecycle phase the process is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Started, not yet serving.
    Starting = 0,
    /// Serving.
    Serving = 1,
    /// Draining: still finishing in-flight work, refusing new work.
    Draining = 2,
    /// Stopped.
    Stopped = 3,
}

/// Overall readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    /// Every required dependency answered `Ready`.
    Ready,
    /// At least one did not.
    NotReady,
    /// Draining. Not ready **on purpose**, so a load balancer stops sending work
    /// while the drain completes (ADR-0002 §11.7 rule 1).
    Draining,
    /// The process has not finished starting.
    Starting,
    /// No readiness probe is registered. Reported as not ready: an unconfigured
    /// `/readyz` that answered 200 would be the "silent outage" of
    /// `infra/README.md` §5.
    NoProbes,
}

impl ReadinessStatus {
    /// Whether `/readyz` should answer 200.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, ReadinessStatus::Ready)
    }

    /// A stable token for the body and for the `outcome` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ReadinessStatus::Ready => "ready",
            ReadinessStatus::NotReady => "not_ready",
            ReadinessStatus::Draining => "draining",
            ReadinessStatus::Starting => "starting",
            ReadinessStatus::NoProbes => "no_probes",
        }
    }
}

/// One dependency's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The probe's name.
    pub name: &'static str,
    /// What it reaches for.
    pub kind: ProbeKind,
    /// Whether it answered `Ready`.
    pub ready: bool,
    /// The registered code when it did not.
    pub reason_code: Option<ReasonCode>,
}

/// The whole readiness answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessReport {
    /// Overall status.
    pub status: ReadinessStatus,
    /// Per-dependency detail.
    pub checks: Vec<CheckReport>,
}

impl ReadinessReport {
    /// The JSON body `/readyz` returns.
    ///
    /// Names and registered codes only: no addresses, no connection strings, no
    /// driver messages. `/readyz` is operator-facing but it is served on a
    /// listener `infra/README.md` §2.1 says "MUST NOT be exposed to an untrusted
    /// network", and a body that leaked a DSN would make that a stronger claim
    /// than it is.
    #[must_use]
    pub fn to_json(&self) -> String {
        let checks: Vec<serde_json::Value> = self
            .checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "kind": format!("{:?}", c.kind),
                    "ready": c.ready,
                    "reason_code": c.reason_code.map(twinvpn_types::ReasonCode::as_str),
                })
            })
            .collect();
        serde_json::json!({ "status": self.status.as_str(), "checks": checks }).to_string()
    }
}

/// Liveness answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessReport {
    /// Whether every invariant holds.
    pub alive: bool,
    /// The invariants that did not hold.
    pub failed: Vec<&'static str>,
}

impl LivenessReport {
    /// The JSON body `/healthz` returns.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "status": if self.alive { "alive" } else { "wedged" },
            "failed_invariants": self.failed,
        })
        .to_string()
    }
}

/// Builds a [`HealthRegistry`].
pub struct HealthBuilder {
    policy: ReadinessPolicy,
    probes: Vec<Arc<dyn DependencyProbe>>,
    liveness: Vec<Arc<dyn LivenessCheck>>,
    probe_timeout: Duration,
    cache_ttl: Duration,
}

impl std::fmt::Debug for HealthBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthBuilder")
            .field("policy", &self.policy)
            .field("probes", &self.probes.len())
            .field("liveness", &self.liveness.len())
            .finish_non_exhaustive()
    }
}

impl HealthBuilder {
    /// Adds a readiness probe.
    ///
    /// # Errors
    ///
    /// [`HealthError::ControlPlaneProbeForbidden`] when the policy is
    /// [`ReadinessPolicy::NoControlPlaneCalls`] and the probe declares
    /// [`ProbeKind::ControlPlane`].
    pub fn readiness(mut self, probe: impl DependencyProbe) -> Result<Self, HealthError> {
        if self.policy == ReadinessPolicy::NoControlPlaneCalls
            && probe.kind() == ProbeKind::ControlPlane
        {
            return Err(HealthError::ControlPlaneProbeForbidden {
                probe: probe.name(),
            });
        }
        self.probes.push(Arc::new(probe));
        Ok(self)
    }

    /// Adds a liveness invariant.
    #[must_use]
    pub fn liveness(mut self, check: impl LivenessCheck) -> Self {
        self.liveness.push(Arc::new(check));
        self
    }

    /// Bounds one probe. A probe that hangs must not hang `/readyz`, because the
    /// container `HEALTHCHECK` has its own timeout and a hung readiness endpoint
    /// is indistinguishable from a dead process.
    #[must_use]
    pub const fn probe_timeout(mut self, d: Duration) -> Self {
        self.probe_timeout = d;
        self
    }

    /// How long a readiness answer is reused.
    ///
    /// Prometheus scrapes `/metrics` and the container `HEALTHCHECK` hits
    /// `/readyz`; without a cache, a probe that opens a database connection runs
    /// on every one of them. Zero disables caching.
    #[must_use]
    pub const fn cache_ttl(mut self, d: Duration) -> Self {
        self.cache_ttl = d;
        self
    }

    /// Finishes.
    #[must_use]
    pub fn build(self) -> HealthRegistry {
        HealthRegistry {
            probes: self.probes,
            liveness: self.liveness,
            probe_timeout: self.probe_timeout,
            cache_ttl: self.cache_ttl,
            state: Arc::new(AtomicU8::new(ServiceState::Starting as u8)),
            cached: Arc::new(Mutex::new(None)),
        }
    }
}

/// Liveness and readiness for one process.
#[derive(Clone)]
pub struct HealthRegistry {
    probes: Vec<Arc<dyn DependencyProbe>>,
    liveness: Vec<Arc<dyn LivenessCheck>>,
    probe_timeout: Duration,
    cache_ttl: Duration,
    state: Arc<AtomicU8>,
    cached: Arc<Mutex<Option<(Instant, ReadinessReport)>>>,
}

impl std::fmt::Debug for HealthRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthRegistry")
            .field("probes", &self.probes.len())
            .field("liveness", &self.liveness.len())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl HealthRegistry {
    /// A builder under `policy`.
    #[must_use]
    pub fn builder(policy: ReadinessPolicy) -> HealthBuilder {
        HealthBuilder {
            policy,
            probes: Vec::new(),
            liveness: Vec::new(),
            probe_timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_millis(500),
        }
    }

    /// How many readiness probes are registered.
    ///
    /// Zero is why [`ReadinessStatus::NoProbes`] exists: a service that reaches
    /// `Serving` with no probe has an unconfigured readiness endpoint, and
    /// `infra/README.md` §5 is explicit that answering 200 there is worse than
    /// having no endpoint at all.
    #[must_use]
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// The current lifecycle phase.
    #[must_use]
    pub fn state(&self) -> ServiceState {
        match self.state.load(Ordering::Relaxed) {
            0 => ServiceState::Starting,
            1 => ServiceState::Serving,
            2 => ServiceState::Draining,
            _ => ServiceState::Stopped,
        }
    }

    /// Moves to a new phase. Invalidates any cached readiness immediately, so a
    /// drain is visible on the very next probe rather than up to `cache_ttl`
    /// later.
    pub fn set_state(&self, state: ServiceState) {
        self.state.store(state as u8, Ordering::Relaxed);
        if let Ok(mut c) = self.cached.lock() {
            *c = None;
        }
    }

    /// `/healthz`.
    #[must_use]
    pub fn liveness(&self) -> LivenessReport {
        let failed: Vec<&'static str> = self
            .liveness
            .iter()
            .filter(|c| !c.holds())
            .map(|c| c.name())
            .collect();
        LivenessReport {
            alive: failed.is_empty(),
            failed,
        }
    }

    /// `/readyz`, evaluating every probe.
    pub async fn readiness(&self) -> ReadinessReport {
        match self.state() {
            ServiceState::Starting => {
                return ReadinessReport {
                    status: ReadinessStatus::Starting,
                    checks: Vec::new(),
                }
            }
            ServiceState::Draining | ServiceState::Stopped => {
                return ReadinessReport {
                    status: ReadinessStatus::Draining,
                    checks: Vec::new(),
                }
            }
            ServiceState::Serving => {}
        }

        if self.probes.is_empty() {
            return ReadinessReport {
                status: ReadinessStatus::NoProbes,
                checks: Vec::new(),
            };
        }

        if !self.cache_ttl.is_zero() {
            if let Ok(guard) = self.cached.lock() {
                if let Some((at, report)) = guard.as_ref() {
                    if at.elapsed() < self.cache_ttl {
                        return report.clone();
                    }
                }
            }
        }

        let mut checks = Vec::with_capacity(self.probes.len());
        for probe in &self.probes {
            let outcome = match tokio::time::timeout(self.probe_timeout, probe.probe()).await {
                Ok(o) => o,
                // A probe that did not answer within its bound is not ready.
                // Treating a timeout as ready is precisely the "converts an
                // outage into a silent one" failure.
                Err(_) => ProbeOutcome::NotReady(codes::CONTROL_UNREACHABLE),
            };
            checks.push(CheckReport {
                name: probe.name(),
                kind: probe.kind(),
                ready: outcome == ProbeOutcome::Ready,
                reason_code: match outcome {
                    ProbeOutcome::Ready => None,
                    ProbeOutcome::NotReady(c) => Some(c),
                },
            });
        }

        let status = if checks.iter().all(|c| c.ready) {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::NotReady
        };
        let report = ReadinessReport { status, checks };

        if !self.cache_ttl.is_zero() {
            if let Ok(mut guard) = self.cached.lock() {
                *guard = Some((Instant::now(), report.clone()));
            }
        }
        report
    }
}
