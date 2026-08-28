//! The two production runtime bindings of ADR-0018 §11.3.
//!
//! > "Two bindings ship: a work-stealing runtime on Linux, Windows, macOS,
//! > Android and OpenWrt (single-threaded scheduler on iOS/iPadOS to stay inside
//! > C-3), and a virtual-time single-threaded runtime for TwinLab. Regardless of
//! > runtime, `Clock`, `Timer` and `Rng` are always injected traits (CD-1), so the
//! > lab's determinism does not depend on the runtime's cooperation."
//!
//! The third — virtual time — is [`crate::virtual_time`], behind `test-support`.
//!
//! `tokio::time` appears here and nowhere else in the workspace: CD-3 bans "the
//! runtime's own time module", and this directory is the one exception.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_core::future::BoxFuture;

use crate::clock::{MonotonicClock, MonotonicInstant};
use crate::error::EnvError;
use crate::task::{Abort, JoinHandle, Runtime, RuntimeKind, Timer};

/// A `tokio` runtime bound as a [`Runtime`] capability.
///
/// Owns the runtime, so dropping this shuts it down. The shell holds it for the
/// life of the process; the core only ever sees the trait.
pub struct TokioRuntime {
    runtime: tokio::runtime::Runtime,
    kind: RuntimeKind,
    shutting_down: Arc<AtomicBool>,
}

impl TokioRuntime {
    // ---------------------------------------------------------------------
    // Both constructors enable BOTH drivers, and the I/O one is not optional.
    //
    // W-43: an earlier revision enabled only `enable_time()`, so no socket,
    // netlink channel or tun device could be registered on a production `Env` —
    // every candidate gather, every probe, every relay leg and the tun device
    // itself need a registered I/O resource. It survived because `MockAdapter`
    // needs no driver and `VirtualTime` needs no I/O, so the whole test tree
    // passed without one: a property every test assumed and none verified.
    //
    // `production_runtime.rs` is the test that verifies it. The drivers are
    // named individually rather than with `enable_all()` — they are the same
    // set today — so that removing one is a visible deletion rather than a
    // silent narrowing.
    // ---------------------------------------------------------------------

    /// The **work-stealing** binding: Linux, Windows, macOS, Android, OpenWrt.
    ///
    /// # Errors
    ///
    /// [`EnvError::SpawnRefused`] if the OS refuses the worker threads.
    pub fn work_stealing() -> Result<Self, EnvError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .thread_name("twinvpn-core")
            .build()
            .map_err(|_| EnvError::SpawnRefused {
                reason: "the OS refused the work-stealing runtime's threads",
            })?;
        Ok(Self {
            runtime,
            kind: RuntimeKind::WorkStealing,
            shutting_down: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The **single-threaded** binding, for iOS and iPadOS.
    ///
    /// §11.3 selects it "to stay inside C-3", the NetworkExtension memory
    /// envelope: worker threads cost stack, and the extension's budget is the
    /// tightest in the §11.9 matrix.
    ///
    /// # Errors
    ///
    /// [`EnvError::SpawnRefused`] if the runtime cannot be built.
    pub fn single_threaded() -> Result<Self, EnvError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| EnvError::SpawnRefused {
                reason: "the single-threaded runtime could not be built",
            })?;
        Ok(Self {
            runtime,
            kind: RuntimeKind::SingleThreaded,
            shutting_down: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The timer capability backed by this runtime.
    ///
    /// Takes the **injected** monotonic clock, because [`Timer::sleep_until`]
    /// receives a deadline on *that* clock's origin and this binding must not
    /// invent a second one. Mixing two monotonic origins is precisely the class
    /// of defect CD-1's distinct types exist to prevent, and it would be
    /// invisible until the two origins drifted.
    ///
    /// A separate object from the runtime, because CD-1 keeps `Timer` injectable
    /// independently: TwinLab pairs a real runtime with a virtual timer, and that
    /// is only possible while the two are separate capabilities.
    #[must_use]
    pub fn timer(&self, monotonic: Arc<dyn MonotonicClock>) -> Arc<dyn Timer> {
        Arc::new(TokioTimer {
            handle: self.runtime.handle().clone(),
            monotonic,
        })
    }
}

impl Runtime for TokioRuntime {
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Result<JoinHandle, EnvError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(EnvError::ShuttingDown);
        }
        let handle = self.runtime.spawn(future);
        Ok(JoinHandle::new(Box::new(TokioAbort {
            inner: handle.abort_handle(),
        })))
    }

    fn kind(&self) -> RuntimeKind {
        self.kind
    }

    fn block_on(&self, future: BoxFuture<'_, ()>) {
        self.runtime.block_on(future);
    }

    fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
    }
}

struct TokioAbort {
    inner: tokio::task::AbortHandle,
}

impl Abort for TokioAbort {
    fn abort(&self) {
        self.inner.abort();
    }
}

/// The timer capability over `tokio::time`.
struct TokioTimer {
    handle: tokio::runtime::Handle,
    monotonic: Arc<dyn MonotonicClock>,
}

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let _guard = self.handle.enter();
        let sleep = tokio::time::sleep(duration);
        Box::pin(sleep)
    }

    fn sleep_until(&self, deadline: MonotonicInstant) -> BoxFuture<'static, ()> {
        // `duration_since` saturates at zero, so a deadline already in the past
        // becomes a zero delay that completes on the next poll — never a timer
        // that silently never fires.
        let delay = deadline.duration_since(self.monotonic.now());
        self.sleep(delay)
    }
}
