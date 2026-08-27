//! The virtual-time binding TwinLab drives. Feature `test-support`.
//!
//! **Authority:** ADR-0018 §11.3 (a virtual-time single-threaded runtime for
//! TwinLab), §11.8 CD-1/CD-5/CD-6, `docs/testing-strategy.md` §3.5.
//!
//! # Why this lives here and not in `lab/`
//!
//! `lab/` is `test-engineering`'s. What TwinLab needs from `core-foundation` is
//! the *shape*: a driver that advances the three clocks **independently**, so a
//! scenario can express "the host was asleep for eight hours" as a fact rather
//! than as a sleep. That shape is inseparable from the clock traits, so it ships
//! here behind a feature and TwinLab drives it.
//!
//! # The property that makes it worth having
//!
//! [`VirtualTime::suspend`] advances [`ElapsedClock`] and the wall clock and
//! leaves [`MonotonicClock`] **exactly where it was**. That is LC-8's rule as an
//! executable fact: a scenario can suspend for eight hours and assert that no
//! `T_DEAD` timer fired, which is precisely the recovery defect ADR-0018 §11.8
//! reason 3 describes and which is otherwise reachable only on real hardware that
//! actually sleeps.
//!
//! # Determinism class
//!
//! This binding gives `BIT` determinism for the core's event sequence. CD-6's
//! residual is unchanged and is restated rather than improved: real kernels,
//! `conntrack`, `netem` and the scheduler are outside any injected provider, so
//! a scenario above level 2 still declares `STATISTICAL` for durations.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use futures_core::future::BoxFuture;

use crate::clock::{
    ElapsedClock, ElapsedInstant, MonotonicClock, MonotonicInstant, WallClock, WallClockReading,
    WallMillis,
};
use crate::error::EnvError;
use crate::task::{Abort, JoinHandle, Runtime, RuntimeKind, Timer};

#[derive(Default)]
struct Inner {
    monotonic_us: u64,
    elapsed_us: u64,
    wall: Option<WallClockReading>,
    /// Deadlines keyed by `(monotonic_us, sequence)`, so two timers at the same
    /// instant fire in registration order rather than in an arbitrary one — the
    /// difference between a `BIT` scenario and a flaky one.
    deadlines: BTreeMap<(u64, u64), Waker>,
    next_seq: u64,
    fired: u64,
}

/// A driver for the three clocks and the timer, advanced explicitly.
#[derive(Clone)]
pub struct VirtualTime {
    inner: Arc<Mutex<Inner>>,
}

impl VirtualTime {
    /// Starts at both clocks' origin, with the supplied wall-clock reading.
    ///
    /// Pass [`WallClockReading::Unset`] to model an RTC-less `GC-0` device
    /// between power-on and its first offset — the CD-1a case, and the one worth
    /// having a scenario for.
    #[must_use]
    pub fn new(wall: WallClockReading) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                wall: Some(wall),
                ..Inner::default()
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a scenario panicked while holding it. Recovering
        // the guard keeps the panic's own report as the visible failure rather
        // than replacing it with a lock panic from the next call.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Advances **all three** clocks: ordinary time passing.
    pub fn advance(&self, by: Duration) {
        let micros = u64::try_from(by.as_micros()).unwrap_or(u64::MAX);
        {
            let mut inner = self.lock();
            inner.monotonic_us = inner.monotonic_us.saturating_add(micros);
            inner.elapsed_us = inner.elapsed_us.saturating_add(micros);
            advance_wall(&mut inner, micros / 1_000);
        }
        self.fire_due();
    }

    /// Advances the **elapsed** and **wall** clocks only. The monotonic clock
    /// does not move, and no timer fires.
    ///
    /// This is LC-8's rule made executable. A scenario asserts, for instance,
    /// that an eight-hour suspend fires no `T_DEAD` (15 s) and no
    /// `T_HEARTBEAT_ACTIVE` (3 s) — the backlog that "would declare every path
    /// dead **before** the wake ladder had a chance to re-validate one".
    pub fn suspend(&self, gap: Duration) {
        let micros = u64::try_from(gap.as_micros()).unwrap_or(u64::MAX);
        let mut inner = self.lock();
        inner.elapsed_us = inner.elapsed_us.saturating_add(micros);
        advance_wall(&mut inner, micros / 1_000);
    }

    /// Sets the wall-clock reading, e.g. when an ADR-0005 relay offset arrives.
    pub fn set_wall(&self, wall: WallClockReading) {
        self.lock().wall = Some(wall);
    }

    /// Advances to the next registered deadline, firing it.
    ///
    /// Returns `false` when no timer is registered — the scenario has stalled and
    /// advancing further would only burn wall time.
    #[must_use]
    pub fn advance_to_next_deadline(&self) -> bool {
        let next = self.lock().deadlines.keys().next().map(|(us, _)| *us);
        match next {
            Some(us) => {
                {
                    let mut inner = self.lock();
                    let step = us.saturating_sub(inner.monotonic_us);
                    inner.monotonic_us = us.max(inner.monotonic_us);
                    inner.elapsed_us = inner.elapsed_us.saturating_add(step);
                    advance_wall(&mut inner, step / 1_000);
                }
                self.fire_due();
                true
            }
            None => false,
        }
    }

    /// How many timers have fired. A cheap `BIT` assertion for a scenario.
    #[must_use]
    pub fn timers_fired(&self) -> u64 {
        self.lock().fired
    }

    /// How many timers are pending.
    #[must_use]
    pub fn timers_pending(&self) -> usize {
        self.lock().deadlines.len()
    }

    /// The monotonic clock capability.
    #[must_use]
    pub fn monotonic(&self) -> Arc<dyn MonotonicClock> {
        Arc::new(self.clone())
    }

    /// The elapsed clock capability.
    #[must_use]
    pub fn elapsed(&self) -> Arc<dyn ElapsedClock> {
        Arc::new(self.clone())
    }

    /// The wall clock capability.
    #[must_use]
    pub fn wall(&self) -> Arc<dyn WallClock> {
        Arc::new(self.clone())
    }

    /// The timer capability.
    #[must_use]
    pub fn timer(&self) -> Arc<dyn Timer> {
        Arc::new(self.clone())
    }

    /// A single-threaded, virtual-time runtime over this driver.
    #[must_use]
    pub fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::new(VirtualRuntime {
            time: self.clone(),
            shutting_down: AtomicBool::new(false),
        })
    }

    fn fire_due(&self) {
        let mut ready = Vec::new();
        {
            let mut inner = self.lock();
            let now = inner.monotonic_us;
            let due: Vec<(u64, u64)> = inner
                .deadlines
                .range(..=(now, u64::MAX))
                .map(|(k, _)| *k)
                .collect();
            for key in due {
                if let Some(waker) = inner.deadlines.remove(&key) {
                    inner.fired += 1;
                    ready.push(waker);
                }
            }
        }
        // Waking outside the lock: a waker may poll synchronously and re-register
        // a timer, which would deadlock against a held guard.
        for w in ready {
            w.wake();
        }
    }

    fn register(&self, deadline_us: u64, waker: Waker) -> Option<(u64, u64)> {
        let mut inner = self.lock();
        if inner.monotonic_us >= deadline_us {
            return None;
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.deadlines.insert((deadline_us, seq), waker);
        Some((deadline_us, seq))
    }

    fn deregister(&self, key: (u64, u64)) {
        self.lock().deadlines.remove(&key);
    }
}

fn advance_wall(inner: &mut Inner, by_millis: u64) {
    // An `Unset` clock does not start ticking because time passed. CD-1a: the
    // device has no wall time until an offset arrives, and manufacturing one from
    // an elapsed count would reintroduce exactly the 1970 reading the three-state
    // value exists to prevent.
    inner.wall = Some(match inner.wall {
        Some(WallClockReading::Offset { millis, source }) => WallClockReading::Offset {
            millis: WallMillis::from_millis(millis.as_millis().saturating_add(by_millis)),
            source,
        },
        Some(WallClockReading::Trusted { millis }) => WallClockReading::Trusted {
            millis: WallMillis::from_millis(millis.as_millis().saturating_add(by_millis)),
        },
        _ => WallClockReading::Unset,
    });
}

impl MonotonicClock for VirtualTime {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_micros(self.lock().monotonic_us)
    }
}

impl ElapsedClock for VirtualTime {
    fn now(&self) -> ElapsedInstant {
        ElapsedInstant::from_micros(self.lock().elapsed_us)
    }
}

impl WallClock for VirtualTime {
    fn now(&self) -> WallClockReading {
        self.lock().wall.unwrap_or(WallClockReading::Unset)
    }
}

impl Timer for VirtualTime {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let deadline = self
            .lock()
            .monotonic_us
            .saturating_add(u64::try_from(duration.as_micros()).unwrap_or(u64::MAX));
        Box::pin(VirtualSleep {
            time: self.clone(),
            deadline_us: deadline,
            key: None,
        })
    }

    fn sleep_until(&self, deadline: MonotonicInstant) -> BoxFuture<'static, ()> {
        Box::pin(VirtualSleep {
            time: self.clone(),
            deadline_us: deadline.as_micros(),
            key: None,
        })
    }
}

struct VirtualSleep {
    time: VirtualTime,
    deadline_us: u64,
    key: Option<(u64, u64)>,
}

impl std::future::Future for VirtualSleep {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if let Some(key) = this.key.take() {
            this.time.deregister(key);
        }
        match this.time.register(this.deadline_us, cx.waker().clone()) {
            Some(key) => {
                this.key = Some(key);
                Poll::Pending
            }
            // Already due. A deadline in the past completes rather than hanging.
            None => Poll::Ready(()),
        }
    }
}

impl Drop for VirtualSleep {
    /// Cancellation is dropping the future, so the registration must go with it —
    /// otherwise a cancelled timer would still hold `advance_to_next_deadline`
    /// hostage and a scenario's timer count would drift.
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.time.deregister(key);
        }
    }
}

/// A deterministic single-threaded runtime over [`VirtualTime`].
///
/// [`Runtime::block_on`] polls, and when the future stalls it advances virtual
/// time to the next registered deadline and polls again. A scenario therefore
/// runs at whatever speed the host manages while *modelling* whatever span it
/// declares — an eight-hour suspend costs no wall time at all.
struct VirtualRuntime {
    time: VirtualTime,
    shutting_down: AtomicBool,
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

impl Runtime for VirtualRuntime {
    fn spawn(&self, future: BoxFuture<'static, ()>) -> Result<JoinHandle, EnvError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(EnvError::ShuttingDown);
        }
        // Deterministically inline: this runtime has one thread and no queue, so
        // spawned work is driven here and now. A scenario that needs concurrency
        // composes futures explicitly, which is also what keeps the interleaving
        // reproducible.
        let mut future = future;
        self.block_on_pinned(&mut future);
        Ok(JoinHandle::new(Box::new(NoAbort)))
    }

    fn kind(&self) -> RuntimeKind {
        RuntimeKind::VirtualTime
    }

    fn block_on(&self, mut future: BoxFuture<'_, ()>) {
        self.block_on_pinned(&mut future);
    }

    fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
    }
}

impl VirtualRuntime {
    fn block_on_pinned(&self, future: &mut BoxFuture<'_, ()>) {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        loop {
            if future.as_mut().poll(&mut cx).is_ready() {
                return;
            }
            if !VirtualTime::advance_to_next_deadline(&self.time) {
                // Stalled with nothing scheduled. Returning is the honest
                // outcome: spinning would hide a scenario deadlock as a hang.
                return;
            }
        }
    }
}

struct NoAbort;

impl Abort for NoAbort {
    fn abort(&self) {}
}
