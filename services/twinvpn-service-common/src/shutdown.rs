//! Graceful shutdown: signal, drain, bounded grace, ordered teardown.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 7, ADR-0002 §11.7
//! rule 1 ("Planned restart is a **drain**. HTTP/3 `GOAWAY` … carries
//! `drain_deadline_ms`, default **120 s**"), `infra/README.md` §4.2 and §7 ("PID
//! 1 is the service, so `SIGTERM` reaches it directly and the graceful shutdown
//! sequence is actually exercised").
//!
//! # The sequence, and why each step is in it
//!
//! ```text
//!   SIGTERM ──▶ 1. state := Draining, /readyz goes RED immediately
//!               2. announce the drain deadline (GOAWAY / close frame)
//!               3. stop admitting new work; wait for in-flight work to finish
//!                  ── bounded by TWINVPN_SHUTDOWN_GRACE_MS
//!               4. ordered teardown of dependencies, each bounded
//!               5. report: drained cleanly, or how much was outstanding
//! ```
//!
//! Step 1 is first because a load balancer that is still sending work to a
//! draining process turns a graceful shutdown into a burst of failed requests.
//! `HealthRegistry::set_state` invalidates the readiness cache, so the red
//! answer is immediate rather than up to one cache TTL late.
//!
//! Step 3 is what makes this graceful rather than a delay: [`InFlight`] guards
//! are counted, and the wait ends when the count reaches zero — not when a timer
//! elapses. The timer is the **bound**, not the mechanism.
//!
//! Step 5 exists because a grace period that silently expires is a grace period
//! nobody knows expired. [`ShutdownReport::drained`] is false and
//! `twinvpn_shutdown_grace_expired_total` increments.
//!
//! # A registry gap, stated
//!
//! There is no registered `reason_code` for "the shutdown grace period expired
//! with work in flight". `INTERNAL.INVARIANT_VIOLATED` would overclaim — grace
//! expiry under load is not necessarily a defect — and inventing a code is not
//! available (`contracts/` is frozen and the registry is append-only). Expiry is
//! therefore reported as a metric plus a `WARN` carrying
//! `twinvpn.outcome="grace_expired"`, both allowlisted. Reported to the
//! integration lead as a finding rather than papered over.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{watch, Notify};

use crate::health::{HealthRegistry, ServiceState};
use crate::metrics::{Labels, Metrics};

/// Shutdown timings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownConfig {
    /// `TWINVPN_SHUTDOWN_GRACE_MS`, default 120 s. How long in-flight work has
    /// to finish before it is abandoned.
    ///
    /// `infra/README.md` §4.2: the container `stop_grace_period` is 130 s so
    /// Docker does not `SIGKILL` a service in the middle of its own drain.
    /// Raising this without raising that is a mistake.
    pub grace: Duration,
    /// `TWINVPN_SHUTDOWN_DRAIN_DEADLINE_MS`, default 120 s. The value announced
    /// to clients in `GOAWAY`; each client picks its reattach instant uniformly
    /// from `[0, deadline)` (ADR-0002 §11.7 rule 1).
    pub drain_deadline: Duration,
    /// Bound on one teardown step.
    pub teardown_step_timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            grace: Duration::from_millis(120_000),
            drain_deadline: Duration::from_millis(120_000),
            teardown_step_timeout: Duration::from_secs(10),
        }
    }
}

type TeardownFn = Box<dyn Fn() -> futures_step::BoxFuture + Send + Sync>;

/// A boxed, `'static` teardown future.
pub mod futures_step {
    use std::future::Future;
    use std::pin::Pin;

    /// The future a teardown step returns.
    pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    /// Boxes `f`.
    pub fn boxed(f: impl Future<Output = ()> + Send + 'static) -> BoxFuture {
        Box::pin(f)
    }
}

struct Step {
    order: u16,
    name: &'static str,
    run: TeardownFn,
}

#[derive(Debug)]
struct Inner {
    draining: AtomicBool,
    inflight: AtomicUsize,
    idle: Notify,
    tx: watch::Sender<bool>,
}

/// The shutdown coordinator. One per process.
pub struct Shutdown {
    inner: Arc<Inner>,
    cfg: ShutdownConfig,
    steps: Mutex<Vec<Step>>,
    health: Option<HealthRegistry>,
    metrics: Metrics,
}

impl std::fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shutdown")
            .field("draining", &self.inner.draining.load(Ordering::Relaxed))
            .field("inflight", &self.inner.inflight.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// One teardown step's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeardownReport {
    /// The step's name.
    pub name: &'static str,
    /// Whether it finished within `teardown_step_timeout`.
    pub completed: bool,
}

/// What the shutdown did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Whether every in-flight operation finished inside the grace period.
    pub drained: bool,
    /// How many were still outstanding when the grace period expired.
    pub outstanding: usize,
    /// Ordered teardown results.
    pub teardown: Vec<TeardownReport>,
}

impl Shutdown {
    /// A coordinator.
    #[must_use]
    pub fn new(cfg: ShutdownConfig, metrics: Metrics) -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            inner: Arc::new(Inner {
                draining: AtomicBool::new(false),
                inflight: AtomicUsize::new(0),
                idle: Notify::new(),
                tx,
            }),
            cfg,
            steps: Mutex::new(Vec::new()),
            health: None,
            metrics,
        }
    }

    /// Wires the health registry so `/readyz` goes red the instant the drain
    /// begins.
    #[must_use]
    pub fn with_health(mut self, health: HealthRegistry) -> Self {
        self.health = Some(health);
        self
    }

    /// The timings.
    #[must_use]
    pub const fn config(&self) -> ShutdownConfig {
        self.cfg
    }

    /// The value to put in `GOAWAY.drain_deadline_ms`.
    #[must_use]
    pub fn drain_deadline_ms(&self) -> u64 {
        u64::try_from(self.cfg.drain_deadline.as_millis()).unwrap_or(u64::MAX)
    }

    /// A handle for the work that must observe the drain.
    #[must_use]
    pub fn handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            inner: self.inner.clone(),
        }
    }

    /// Registers an ordered teardown step.
    ///
    /// Steps run in ascending `order` **after** the drain, so a database pool
    /// closed at order 10 is still open while in-flight requests finish, and the
    /// OTLP exporter shut down at order 90 still carries the records describing
    /// the drain. Ties keep registration order.
    ///
    /// # Panics
    ///
    /// If the teardown registry mutex was poisoned by a panic in another thread.
    pub fn register_teardown<F>(&self, order: u16, name: &'static str, run: F)
    where
        F: Fn() -> futures_step::BoxFuture + Send + Sync + 'static,
    {
        self.steps
            .lock()
            .expect("teardown registry poisoned")
            .push(Step {
                order,
                name,
                run: Box::new(run),
            });
    }

    /// Resolves when `SIGTERM` or `SIGINT` arrives.
    ///
    /// `infra/README.md` §7: PID 1 is the service, so `SIGTERM` reaches it
    /// directly — there is no shell and no init wrapper to swallow it.
    ///
    /// # Panics
    ///
    /// If the process cannot install a `SIGTERM` handler. A service that cannot
    /// hear `SIGTERM` cannot shut down gracefully, and pretending otherwise is
    /// worse than failing at startup.
    pub async fn wait_for_signal() {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }

    /// Runs the whole sequence.
    ///
    /// Marks the service draining, waits for in-flight work up to `grace`, then
    /// runs the teardown steps in order.
    ///
    /// # Panics
    ///
    /// If the teardown registry mutex was poisoned by a panic in another thread.
    pub async fn shutdown(&self) -> ShutdownReport {
        // 1. Refuse new work and go red, before anything else.
        self.inner.draining.store(true, Ordering::SeqCst);
        // `send_replace`, not `send`: `send` fails when no receiver currently
        // exists and then does NOT update the value, so a task that subscribes
        // afterwards would see `false` and wait for a change that already
        // happened. That is a hang, not a missed notification.
        self.inner.tx.send_replace(true);
        if let Some(h) = &self.health {
            h.set_state(ServiceState::Draining);
        }
        self.metrics
            .gauge(
                crate::metrics::names::DRAINING,
                "1 once a drain has begun",
                Labels::new(),
            )
            .set(1);
        tracing::info!(
            twinvpn.outcome = "drain_started",
            "draining before shutdown"
        );

        // 2. Wait for in-flight work. The wait ends on the COUNT, not the timer.
        let drained = self.wait_for_idle().await;
        let outstanding = self.inner.inflight.load(Ordering::SeqCst);

        if drained {
            tracing::info!(twinvpn.outcome = "drained", "all in-flight work completed");
        } else {
            self.metrics
                .counter(
                    crate::metrics::names::SHUTDOWN_GRACE_EXPIRED,
                    "shutdown grace periods that expired with work in flight",
                    Labels::new(),
                )
                .inc();
            self.metrics
                .gauge(
                    crate::metrics::names::SHUTDOWN_INFLIGHT_AT_DEADLINE,
                    "operations outstanding when the grace period expired",
                    Labels::new(),
                )
                .set(i64::try_from(outstanding).unwrap_or(i64::MAX));
            tracing::warn!(
                twinvpn.outcome = "grace_expired",
                twinvpn.dropped_events = u64::try_from(outstanding).unwrap_or(u64::MAX),
                "the shutdown grace period expired with work still in flight"
            );
        }

        // 3. Ordered teardown.
        let mut steps: Vec<(u16, &'static str, futures_step::BoxFuture)> = {
            let guard = self.steps.lock().expect("teardown registry poisoned");
            let mut v: Vec<_> = guard
                .iter()
                .enumerate()
                .map(|(i, s)| (s.order, i, s.name, (s.run)()))
                .collect();
            v.sort_by_key(|(order, i, _, _)| (*order, *i));
            v.into_iter().map(|(o, _, n, f)| (o, n, f)).collect()
        };

        let mut teardown = Vec::with_capacity(steps.len());
        for (_, name, fut) in steps.drain(..) {
            let completed = tokio::time::timeout(self.cfg.teardown_step_timeout, fut)
                .await
                .is_ok();
            if !completed {
                tracing::warn!(
                    twinvpn.outcome = "teardown_timeout",
                    "a teardown step did not finish within its bound"
                );
            }
            teardown.push(TeardownReport { name, completed });
        }

        if let Some(h) = &self.health {
            h.set_state(ServiceState::Stopped);
        }

        ShutdownReport {
            drained,
            outstanding,
            teardown,
        }
    }

    async fn wait_for_idle(&self) -> bool {
        let inner = self.inner.clone();
        let wait = async move {
            loop {
                if inner.inflight.load(Ordering::SeqCst) == 0 {
                    return;
                }
                inner.idle.notified().await;
            }
        };
        tokio::time::timeout(self.cfg.grace, wait).await.is_ok()
    }
}

/// The half of [`Shutdown`] that work holds.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    inner: Arc<Inner>,
}

impl ShutdownHandle {
    /// Whether a drain has begun.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::SeqCst)
    }

    /// Resolves when the drain begins. Returns immediately if it already has.
    pub async fn draining(&self) {
        let mut rx = self.inner.tx.subscribe();
        // Both checks: the flag is the authority, the watch is the wakeup.
        if self.is_draining() || *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }

    /// Registers one in-flight operation, if the service is still admitting.
    ///
    /// Returns `None` once draining has begun, which is how "stop accepting new
    /// work" is expressed: the caller answers with
    /// `CONTROL.ADMISSION_DEFERRED{retry_after_ms}` rather than starting work
    /// that cannot finish. ADR-0002 §11.7 rule 3 (**S-6**) is explicit that a TCP
    /// reset or a silent drop is prohibited here.
    #[must_use]
    pub fn try_acquire(&self) -> Option<InFlight> {
        if self.is_draining() {
            return None;
        }
        self.inner.inflight.fetch_add(1, Ordering::SeqCst);
        // Re-check: a drain that began between the test and the increment would
        // otherwise leave a guard the drain never waited for. Losing the race
        // means releasing immediately, which is correct.
        if self.is_draining() {
            let guard = InFlight {
                inner: self.inner.clone(),
            };
            drop(guard);
            return None;
        }
        Some(InFlight {
            inner: self.inner.clone(),
        })
    }

    /// Registers an in-flight operation **even while draining**.
    ///
    /// For work that is part of the drain itself: flushing a queue, answering a
    /// request already accepted, writing a final event.
    #[must_use]
    pub fn acquire_unconditionally(&self) -> InFlight {
        self.inner.inflight.fetch_add(1, Ordering::SeqCst);
        InFlight {
            inner: self.inner.clone(),
        }
    }

    /// How many operations are in flight.
    #[must_use]
    pub fn inflight(&self) -> usize {
        self.inner.inflight.load(Ordering::SeqCst)
    }
}

/// One in-flight operation. The drain waits for every one of these to drop.
#[derive(Debug)]
pub struct InFlight {
    inner: Arc<Inner>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.inner.inflight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.inner.idle.notify_waiters();
        }
    }
}
