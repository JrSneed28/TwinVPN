//! The `Timer` and `Runtime` capabilities.
//!
//! **Authority:** ADR-0018 §11.3 ("the core is `async`, over a `Runtime`
//! capability"; two bindings ship, plus a virtual-time one for TwinLab), §11.8
//! CD-1/CD-2, `docs/architecture.md` §5.2 R-DET-1 property 1.
//!
//! # A timer is not a clock read
//!
//! R-DET-1 is explicit that this is a separate defect: "A component may hold a
//! correctly injected clock and still call the runtime's `sleep`/`after`/
//! `interval`, which is a scheduling dependency on real time that no clock
//! injection catches." `docs/reliability.md` §5 defines about thirty named
//! timers, so omitting them would leave most of the determinism surface
//! unaddressed.
//!
//! [`Timer`] is therefore its own capability, and CD-3's deny-list bans the
//! runtime's own time module everywhere outside this crate's bindings.
//!
//! # Only the monotonic clock can drive a timer
//!
//! [`Timer::sleep_until`] takes a [`MonotonicInstant`] and nothing else. An
//! [`crate::ElapsedInstant`] does not convert to one, so LC-8's "never used for:
//! driving a liveness or recovery timer" is a compile error rather than a review
//! comment.

use core::time::Duration;

use futures_core::future::BoxFuture;

use crate::clock::MonotonicInstant;
use crate::error::EnvError;

/// Scheduled waiting, on the suspend-exclusive monotonic clock.
pub trait Timer: Send + Sync {
    /// Completes after `duration` of monotonic time.
    ///
    /// Cancellation is dropping the returned future. A binding **must** release
    /// the timer's registration on drop, so a cancelled operation costs nothing
    /// after cancellation.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;

    /// Completes at or after `deadline`.
    ///
    /// Returns an already-complete future if `deadline` is in the past, rather
    /// than never firing — a deadline computed before a slow step is a normal
    /// occurrence, not a reason to hang.
    fn sleep_until(&self, deadline: MonotonicInstant) -> BoxFuture<'static, ()>;
}

/// Which scheduler a [`Runtime`] binding is.
///
/// A **domain fact**, not an OS fact, so reading it is not a CB-3 violation:
/// TwinLab asserts `VirtualTime` before declaring a `BIT` scenario, and a
/// component with a blocking section can refuse to run on `SingleThreaded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RuntimeKind {
    /// The work-stealing multi-threaded scheduler: Linux, Windows, macOS,
    /// Android, OpenWrt (ADR-0018 §11.3).
    WorkStealing,
    /// The single-threaded scheduler, used on iOS and iPadOS to stay inside the
    /// C-3 extension memory envelope.
    SingleThreaded,
    /// TwinLab's virtual-time scheduler.
    VirtualTime,
}

/// A handle to spawned work.
///
/// Dropping it does **not** cancel the task — that would make an ignored handle
/// a silent cancellation. [`JoinHandle::abort`] is explicit.
pub struct JoinHandle {
    inner: Box<dyn Abort>,
}

impl JoinHandle {
    /// Wraps a binding's abort handle.
    #[must_use]
    pub fn new(inner: Box<dyn Abort>) -> Self {
        Self { inner }
    }

    /// Requests cancellation. Idempotent, and safe after the task has finished.
    pub fn abort(&self) {
        self.inner.abort();
    }
}

impl core::fmt::Debug for JoinHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JoinHandle")
    }
}

/// A binding's cancellation handle.
pub trait Abort: Send + Sync {
    /// Requests cancellation. Must be idempotent.
    fn abort(&self);
}

/// The async scheduler, as an injected capability.
pub trait Runtime: Send + Sync {
    /// Spawns work.
    ///
    /// # Errors
    ///
    /// [`EnvError::ShuttingDown`] once graceful shutdown has begun, and
    /// [`EnvError::SpawnRefused`] if the binding declines for any other reason.
    /// A refused spawn is reported, never dropped: silently discarding work is
    /// how a shutdown appears to succeed while leaving a job undone.
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Result<JoinHandle, EnvError>;

    /// Which scheduler this is.
    fn kind(&self) -> RuntimeKind;

    /// Drives `future` to completion on this runtime.
    ///
    /// The entry point the FFI boundary and the daemon's `main` use. A component
    /// inside the core never calls it — doing so from inside a runtime is a
    /// deadlock on the single-threaded binding.
    fn block_on(&self, future: BoxFuture<'_, ()>);

    /// Begins graceful shutdown: refuse new spawns, let running work finish.
    ///
    /// Idempotent. `ownership.md` §6 rule 7 requires graceful shutdown, and a
    /// runtime that cannot refuse new work cannot provide it — the queue would
    /// grow for as long as anything kept submitting.
    fn begin_shutdown(&self);
}
