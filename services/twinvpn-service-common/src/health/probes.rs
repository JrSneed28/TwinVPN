//! The readiness and liveness abstractions the four service domains implement.
//!
//! Split out of `health/mod.rs` to keep both files under the 500-line limit in
//! `CLAUDE.md`. The module re-exports every item, so the path a consumer
//! writes is `twinvpn_service_common::health::FnProbe` either way.

use std::future::Future;
use std::pin::Pin;

use twinvpn_types::ReasonCode;

/// A boxed probe future.
pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = ProbeOutcome> + Send + 'a>>;

/// What a readiness probe reaches for.
///
/// Declared rather than inferred, because the point of the declaration is that a
/// reviewer and [`super::ReadinessPolicy`] can both see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// In-process state only: a key set parsed, a listener bound, a config
    /// invariant. Never touches the network.
    Local,
    /// A datastore this service owns a connection to.
    Datastore,
    /// **A call to the control plane.** Forbidden on the data plane (I5).
    ControlPlane,
    /// Another infrastructure service that is not the control plane.
    Peer,
}

/// The result of one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The dependency is available.
    Ready,
    /// It is not, and here is the registered code that says why.
    NotReady(ReasonCode),
}

/// A readiness dependency.
pub trait DependencyProbe: Send + Sync + 'static {
    /// A short, static, low-cardinality name. Appears in the `/readyz` body,
    /// never as a metric label (ADR-0015 §9 admits five label dimensions and this
    /// is not one of them).
    fn name(&self) -> &'static str;

    /// What this probe reaches for.
    fn kind(&self) -> ProbeKind;

    /// Runs the probe. MUST be cancellation-safe: it is raced against a timeout.
    fn probe(&self) -> ProbeFuture<'_>;
}

/// A liveness invariant: cheap, synchronous, and about *this process only*.
///
/// A liveness check that touches the network converts a dependency outage into a
/// restart loop, which is the failure `/readyz` exists to keep separate.
pub trait LivenessCheck: Send + Sync + 'static {
    /// A short, static name.
    fn name(&self) -> &'static str;
    /// Whether the invariant holds.
    fn holds(&self) -> bool;
}

/// A probe built from a closure, for the common case.
pub struct FnProbe<F> {
    name: &'static str,
    kind: ProbeKind,
    f: F,
}

impl<F, Fut> FnProbe<F>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ProbeOutcome> + Send + 'static,
{
    /// Wraps `f`.
    pub const fn new(name: &'static str, kind: ProbeKind, f: F) -> Self {
        Self { name, kind, f }
    }
}

impl<F, Fut> DependencyProbe for FnProbe<F>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ProbeOutcome> + Send + 'static,
{
    fn name(&self) -> &'static str {
        self.name
    }
    fn kind(&self) -> ProbeKind {
        self.kind
    }
    fn probe(&self) -> ProbeFuture<'_> {
        Box::pin((self.f)())
    }
}

/// A liveness invariant built from a closure.
pub struct FnLiveness<F> {
    name: &'static str,
    f: F,
}

impl<F: Fn() -> bool + Send + Sync + 'static> FnLiveness<F> {
    /// Wraps `f`.
    pub const fn new(name: &'static str, f: F) -> Self {
        Self { name, f }
    }
}

impl<F: Fn() -> bool + Send + Sync + 'static> LivenessCheck for FnLiveness<F> {
    fn name(&self) -> &'static str {
        self.name
    }
    fn holds(&self) -> bool {
        (self.f)()
    }
}
