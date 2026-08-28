//! Cancellation for the packet pump: a token, and the race that makes a
//! blocking wait give it up.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 7 (graceful
//! shutdown); `twinvpn_platform::socket::UdpSocket`'s own contract
//! (*"cancellation is dropping the future"*); ADR-0018 CD-3 — nothing here
//! reads a clock, so no deny-listed call is reachable from it.
//!
//! # Why this exists rather than a combinator
//!
//! [`super::Pump`]'s inbound half blocks in `recv_from` until a datagram
//! arrives, and a datagram may never arrive. A pump that only checked a flag
//! between iterations would therefore never observe a shutdown request on an
//! idle tunnel — it would hold the runtime open for as long as the peer stayed
//! silent, which is precisely the failure rule 7 exists to forbid. The wait has
//! to be **raced** against the request, and `twinvpn-core` declares no
//! combinator crate, so the race is written here.
//!
//! # Cancellation is checked before the work, never during it
//!
//! [`Race`] polls the token **first** on every poll. Once the work future has
//! produced a packet, the pump does not consult the token again until that
//! packet has been carried all the way to the far side — so a cancellation can
//! never land between `open` and `write_packet` and leave a half-written packet
//! on the interface. Promptness is bought at the blocking wait, which is where
//! all the waiting actually is.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures_core::future::BoxFuture;

/// A shared, cloneable request to stop.
///
/// Tripping it is **idempotent** and safe from any holder: the pump, the
/// composition root's shutdown path and a test all hold the same token.
#[derive(Debug, Clone, Default)]
pub struct Cancel {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    tripped: AtomicBool,
    /// One slot per live [`Cancelled`] future. Slots are stable for the life of
    /// the future that owns them — [`Cancel::cancel`] takes each waker out *in
    /// place* rather than draining the vector — because an index that moved
    /// under a live future would have it clear somebody else's registration on
    /// drop.
    waiters: Mutex<Vec<Option<Waker>>>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned waiter list is a list of wakers, not key material: taking it
    // back is safe, and refusing to would turn one panic elsewhere into a pump
    // that can never be stopped.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Cancel {
    /// A token that has not been tripped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests that every holder stop. Idempotent.
    pub fn cancel(&self) {
        self.inner.tripped.store(true, Ordering::Release);
        let woken: Vec<Waker> = {
            let mut waiters = guard(&self.inner.waiters);
            waiters.iter_mut().filter_map(Option::take).collect()
        };
        // Woken outside the lock: a waker may poll the future it belongs to
        // inline, and that future takes this same lock.
        for waker in woken {
            waker.wake();
        }
    }

    /// Whether the token has been tripped.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.tripped.load(Ordering::Acquire)
    }

    /// A future that completes when the token is tripped.
    #[must_use]
    pub fn cancelled(&self) -> Cancelled {
        Cancelled {
            token: self.clone(),
            slot: None,
        }
    }
}

/// The future half of a [`Cancel`].
///
/// Holds at most one registration, released on drop, so a pump that builds one
/// per loop iteration does not grow the waiter list for the life of the
/// session.
#[derive(Debug)]
pub struct Cancelled {
    token: Cancel,
    slot: Option<usize>,
}

impl Future for Cancelled {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Cancelled { token, slot } = self.get_mut();
        if token.is_cancelled() {
            return Poll::Ready(());
        }
        let mut waiters = guard(&token.inner.waiters);
        // Re-checked **under the lock**. `Cancel::cancel` sets the flag and then
        // takes every waker under this same lock, so a trip that lands between
        // the check above and the registration below is caught here rather than
        // parking a waker nobody will ever wake.
        if token.is_cancelled() {
            return Poll::Ready(());
        }
        let index = if let Some(index) = *slot {
            index
        } else {
            let index = waiters.iter().position(Option::is_none).unwrap_or_else(|| {
                waiters.push(None);
                waiters.len() - 1
            });
            *slot = Some(index);
            index
        };
        waiters[index] = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Cancelled {
    fn drop(&mut self) {
        if let Some(index) = self.slot {
            let mut waiters = guard(&self.token.inner.waiters);
            if let Some(entry) = waiters.get_mut(index) {
                *entry = None;
            }
        }
    }
}

/// What a [`Race`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Raced<T> {
    /// The work finished first.
    Completed(T),
    /// The token was tripped first. The work future has been **dropped**, which
    /// is how `UdpSocket` and `TunnelDevice` both define cancellation.
    Cancelled,
}

/// One blocking wait, raced against a cancellation request.
///
/// `Unpin` by construction — a [`BoxFuture`] is already `Pin<Box<..>>` and
/// [`Cancelled`] holds nothing self-referential — which is what lets this
/// project to its fields under the crate's `#![forbid(unsafe_code)]`.
pub struct Race<'a, T> {
    work: BoxFuture<'a, T>,
    cancel: Cancelled,
}

/// Races `work` against `cancel`.
#[must_use]
pub fn race<T>(work: BoxFuture<'_, T>, cancel: Cancelled) -> Race<'_, T> {
    Race { work, cancel }
}

impl<T> Future for Race<'_, T> {
    type Output = Raced<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Raced<T>> {
        let me = self.get_mut();
        // Cancellation first, always. A work future that is ready on every poll
        // would otherwise starve the token, and a pump on a saturated tunnel
        // would never stop.
        if Pin::new(&mut me.cancel).poll(cx).is_ready() {
            return Poll::Ready(Raced::Cancelled);
        }
        match me.work.as_mut().poll(cx) {
            Poll::Ready(value) => Poll::Ready(Raced::Completed(value)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{guard, race, Cancel, Raced};
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use futures_core::future::BoxFuture;

    fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        Pin::new(future).poll(&mut cx)
    }

    #[test]
    fn a_fresh_token_is_pending_and_a_tripped_one_is_ready() {
        let token = Cancel::new();
        let mut cancelled = token.cancelled();
        assert_eq!(poll_once(&mut cancelled), Poll::Pending);
        token.cancel();
        assert_eq!(poll_once(&mut cancelled), Poll::Ready(()));
    }

    #[test]
    fn cancelling_twice_is_idempotent() {
        let token = Cancel::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn a_dropped_waiter_releases_its_slot() {
        // The property that keeps a pump's per-iteration `cancelled()` from
        // growing the waiter list for the life of the session.
        let token = Cancel::new();
        for _ in 0..64 {
            let mut cancelled = token.cancelled();
            assert_eq!(poll_once(&mut cancelled), Poll::Pending);
        }
        assert_eq!(guard(&token.inner.waiters).len(), 1);
    }

    #[test]
    fn a_race_gives_up_a_pending_wait() {
        let token = Cancel::new();
        let never: BoxFuture<'static, u8> = Box::pin(core::future::pending());
        let mut raced = race(never, token.cancelled());
        assert_eq!(poll_once(&mut raced), Poll::Pending);
        token.cancel();
        assert_eq!(poll_once(&mut raced), Poll::Ready(Raced::Cancelled));
    }

    #[test]
    fn a_ready_work_future_still_loses_to_an_already_tripped_token() {
        // Cancellation is checked first on every poll, so shutdown stays
        // reachable on a tunnel that is saturated with traffic.
        let token = Cancel::new();
        token.cancel();
        let ready: BoxFuture<'static, u8> = Box::pin(core::future::ready(7));
        let mut raced = race(ready, token.cancelled());
        assert_eq!(poll_once(&mut raced), Poll::Ready(Raced::Cancelled));
    }
}
