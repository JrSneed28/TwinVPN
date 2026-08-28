//! [`InterfaceProvider`]: the snapshot the JNI layer feeds, and the change
//! stream the core selects on.
//!
//! **Authority:** `docs/networking.md` §5.1 (`subscribe_network_change(cb)` —
//! "event-driven, never polled"), §5.2's Android row; ADR-0018 §11.6 ("a dropped
//! event is itself recorded"), F-9's inversion; [`twinvpn_platform::iface`].
//!
//! # Event-driven, and that is a property of the whole path
//!
//! `ConnectivityManager.NetworkCallback` is a callback. Nothing in this module
//! polls, and nothing in it has a timer — there is no place to put one, because
//! [`AndroidInterfaceProvider`] has no clock. §5.1's rule is not about
//! efficiency: *"a poll interval is a window in which the host has moved
//! networks and the core still believes it has not"*, and every roaming deadline
//! in `docs/reliability.md` §5 is measured from the moment the change is known.
//!
//! # Backpressure: a bounded queue and an honest gap
//!
//! Each subscriber holds a bounded queue. When it overflows, the **oldest**
//! entries are dropped and a count is carried, delivered as
//! [`NetworkChange::EventsLost`] on the next poll. ADR-0018 §11.6: *"a dropped
//! event is itself recorded"* — an adapter that silently coalesced would leave
//! the core believing it has a complete picture, while one that reports the gap
//! lets the core re-enumerate and recover.
//!
//! Dropping the **oldest** rather than the newest is deliberate: after a burst,
//! the newest events are the ones that describe the network the device is
//! actually on. Keeping stale ones and refusing fresh ones would hand the core a
//! picture that is both incomplete *and* out of date.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures_core::future::BoxFuture;
use futures_core::Stream;

use twinvpn_platform::iface::{InterfaceFacts, InterfaceIndex, InterfaceProvider, NetworkChange};
use twinvpn_platform::PlatformError;

use crate::netchange::{diff, AndroidNetwork, Snapshot};
use crate::shutdown::ShutdownLatch;

/// How many changes one subscriber may fall behind by before events are lost.
///
/// `ConnectivityManager` can deliver a burst on a handoff — `onLost`,
/// `onAvailable`, several `onCapabilitiesChanged` and `onLinkPropertiesChanged`
/// — and a core that is mid-`apply` may not drain for a moment. 256 absorbs
/// every burst observed in the wild with room to spare, and it is a **bound**
/// rather than a target: exceeding it is reported, not silently tolerated.
pub const SUBSCRIBER_QUEUE_DEPTH: usize = 256;

/// One subscriber's queue.
#[derive(Debug, Default)]
struct Subscriber {
    queue: VecDeque<NetworkChange>,
    lost: u64,
    waker: Option<Waker>,
    closed: bool,
}

impl Subscriber {
    fn push(&mut self, change: &NetworkChange) {
        if self.queue.len() >= SUBSCRIBER_QUEUE_DEPTH {
            // Drop the oldest and count it. See the module documentation for
            // why the oldest and not the newest.
            self.queue.pop_front();
            self.lost = self.lost.saturating_add(1);
        }
        self.queue.push_back(change.clone());
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// Interface enumeration and change notification, over the snapshot the JNI
/// layer maintains.
#[derive(Debug, Clone)]
pub struct AndroidInterfaceProvider {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    snapshot: Mutex<Snapshot>,
    subscribers: Mutex<Vec<Arc<Mutex<Subscriber>>>>,
    /// The tun's interface index once it exists, so `is_overlay` is answered
    /// from a fact rather than from a name prefix.
    ///
    /// Android has no interface *kind* on the Java side, and a name test
    /// (`tun0`, `twin0`) would classify another product's tunnel as ours —
    /// which would make ADR-0012's interface-scoped reasoning permit somebody
    /// else's traffic. The overlay index is recorded by [`crate::netcfg`] at
    /// `apply`, which is the only place that genuinely knows.
    overlay: Mutex<Option<InterfaceIndex>>,
    shutdown: ShutdownLatch,
}

impl AndroidInterfaceProvider {
    /// Builds a provider with no networks observed yet.
    #[must_use]
    pub fn new(shutdown: ShutdownLatch) -> Self {
        Self {
            inner: Arc::new(Inner {
                snapshot: Mutex::new(Snapshot::new()),
                subscribers: Mutex::new(Vec::new()),
                overlay: Mutex::new(None),
                shutdown,
            }),
        }
    }

    /// Records which interface index is our own overlay.
    pub fn set_overlay(&self, index: Option<InterfaceIndex>) {
        if let Ok(mut slot) = self.inner.overlay.lock() {
            *slot = index;
        }
    }

    /// Replaces one network and publishes the resulting changes.
    ///
    /// Called from `onAvailable`, `onCapabilitiesChanged` and
    /// `onLinkPropertiesChanged`. The diff is what turns Android's
    /// whole-current-state callbacks into the seam's deltas.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the tracked set is full
    /// ([`crate::netchange::MAX_TRACKED_NETWORKS`]) or the lock is poisoned.
    pub fn ingest(&self, network: AndroidNetwork) -> Result<(), PlatformError> {
        self.mutate(|snapshot| snapshot.ingest(network))
    }

    /// Removes one network and publishes the resulting changes (`onLost`).
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the lock is poisoned.
    pub fn forget(&self, handle: u64) -> Result<(), PlatformError> {
        self.mutate(|snapshot| {
            snapshot.forget(handle);
            Ok(())
        })
    }

    /// Records the power posture and publishes it if it changed.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the lock is poisoned.
    pub fn set_power(&self, metered: bool, low_power: bool) -> Result<(), PlatformError> {
        self.mutate(|snapshot| {
            snapshot.set_power(metered, low_power);
            Ok(())
        })
    }

    /// The snapshot as it stands, for [`crate::netcfg`]'s `query_link_facts`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the lock is poisoned.
    pub fn snapshot(&self) -> Result<Snapshot, PlatformError> {
        self.inner
            .snapshot
            .lock()
            .map(|s| s.clone())
            .map_err(|_| crate::oserr::unavailable("iface.snapshot", libc::EDEADLK))
    }

    /// Applies `change` to the snapshot, diffs, and fans the result out.
    fn mutate<F>(&self, change: F) -> Result<(), PlatformError>
    where
        F: FnOnce(&mut Snapshot) -> Result<(), PlatformError>,
    {
        // NOT gated on the shutdown latch. A network change that arrives while
        // the adapter is shutting down is still a fact, and refusing to record
        // it would leave the snapshot describing a network the device has left
        // -- which the next process reads at rehydration.
        let changes = {
            let mut guard = self
                .inner
                .snapshot
                .lock()
                .map_err(|_| crate::oserr::unavailable("iface.mutate", libc::EDEADLK))?;
            let before = guard.clone();
            change(&mut guard)?;
            diff(&before, &guard)
        };
        if changes.is_empty() {
            return Ok(());
        }
        self.publish(&changes);
        Ok(())
    }

    /// Fans changes out to every live subscriber, pruning closed ones.
    fn publish(&self, changes: &[NetworkChange]) {
        let Ok(mut subscribers) = self.inner.subscribers.lock() else {
            return;
        };
        subscribers.retain(|subscriber| {
            let Ok(mut state) = subscriber.lock() else {
                return false;
            };
            if state.closed {
                return false;
            }
            for change in changes {
                state.push(change);
            }
            true
        });
    }
}

impl InterfaceProvider for AndroidInterfaceProvider {
    fn enumerate(&self) -> BoxFuture<'_, Result<Vec<InterfaceFacts>, PlatformError>> {
        Box::pin(async move {
            self.inner.shutdown.check()?;
            let overlay = self.inner.overlay.lock().ok().and_then(|slot| *slot);
            let snapshot = self.snapshot()?;
            Ok(snapshot
                .networks()
                .iter()
                .map(|n| n.facts(Some(n.index()) == overlay))
                .collect())
        })
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        self.inner.shutdown.check()?;
        let state = Arc::new(Mutex::new(Subscriber::default()));
        self.inner
            .subscribers
            .lock()
            .map_err(|_| crate::oserr::unavailable("iface.subscribe", libc::EDEADLK))?
            .push(Arc::clone(&state));
        Ok(Box::pin(ChangeStream { state }))
    }
}

/// One subscriber's view of the change stream.
///
/// Deliberately **not** a replay of the current state: `subscribe`'s contract is
/// that the stream carries changes and not initial state, and *"an adapter that
/// replayed the initial state as a burst of `Added` events would make 'we just
/// started' and 'the network just changed' indistinguishable"*.
struct ChangeStream {
    state: Arc<Mutex<Subscriber>>,
}

impl Stream for ChangeStream {
    type Item = NetworkChange;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<NetworkChange>> {
        let Ok(mut state) = self.state.lock() else {
            return Poll::Ready(None);
        };
        // The gap is reported BEFORE the events that survived it, so a core that
        // re-enumerates on `EventsLost` does so before acting on a partial view.
        if state.lost > 0 {
            let count = state.lost;
            state.lost = 0;
            return Poll::Ready(Some(NetworkChange::EventsLost { count: Some(count) }));
        }
        if let Some(change) = state.queue.pop_front() {
            return Poll::Ready(Some(change));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for ChangeStream {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.queue.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netchange::TransportSet;
    use twinvpn_platform::iface::{InterfaceName, LinkClass};
    use twinvpn_types::{AddressFamily, PerFamily};

    fn net(handle: u64, transports: u32) -> AndroidNetwork {
        AndroidNetwork {
            handle,
            name: InterfaceName::new("wlan0").expect("name"),
            transports: TransportSet::from_bits(transports),
            addresses: Vec::new(),
            default_routes: PerFamily::new(true, true),
            resolvers: Vec::new(),
            mtu: 1500,
            metered: false,
            nat64: None,
            private_dns_active: false,
            is_up: true,
        }
    }

    /// A tiny executor: the seam's futures are `BoxFuture`s and this crate has
    /// no runtime dependency in its unit tests.
    fn block_on<T>(mut future: BoxFuture<'_, T>) -> T {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Flag(AtomicBool);
        impl std::task::Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                return value;
            }
            std::thread::yield_now();
        }
    }

    fn poll_once(
        stream: &mut Pin<Box<dyn Stream<Item = NetworkChange> + Send>>,
    ) -> Option<NetworkChange> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match stream.as_mut().poll_next(&mut cx) {
            Poll::Ready(item) => item,
            Poll::Pending => None,
        }
    }

    #[test]
    fn a_new_subscriber_receives_changes_and_not_the_initial_state() {
        let provider = AndroidInterfaceProvider::new(ShutdownLatch::new());
        provider.ingest(net(1, TransportSet::WIFI)).expect("ingest");

        let mut stream = provider.subscribe().expect("subscribe");
        assert_eq!(poll_once(&mut stream), None, "no replay");

        provider
            .ingest(net(2, TransportSet::CELLULAR))
            .expect("ingest");
        assert!(matches!(
            poll_once(&mut stream),
            Some(NetworkChange::InterfaceAdded(_))
        ));
    }

    #[test]
    fn enumerate_reports_what_the_snapshot_holds_with_the_overlay_named() {
        let provider = AndroidInterfaceProvider::new(ShutdownLatch::new());
        let underlay = net(1, TransportSet::WIFI);
        let overlay = net(2, TransportSet::VPN);
        let overlay_index = overlay.index();
        provider.ingest(underlay).expect("ingest");
        provider.ingest(overlay).expect("ingest");
        provider.set_overlay(Some(overlay_index));

        let facts = block_on(provider.enumerate()).expect("enumerate");
        assert_eq!(facts.len(), 2);
        let ours: Vec<_> = facts.iter().filter(|f| f.is_overlay).collect();
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0].index, overlay_index);
        assert_eq!(ours[0].link_class, LinkClass::Tunnel);
        // Both default-route flags reach the core separately (R6).
        assert!(facts[0].has_default_route(AddressFamily::V4));
        assert!(facts[0].has_default_route(AddressFamily::V6));
    }

    #[test]
    fn is_overlay_is_answered_from_a_recorded_index_not_from_a_name() {
        // Another product's tunnel is `Tunnel`-classed but is NOT ours, and
        // treating it as ours would make ADR-0012's interface-scoped reasoning
        // permit somebody else's traffic.
        let provider = AndroidInterfaceProvider::new(ShutdownLatch::new());
        provider.ingest(net(7, TransportSet::VPN)).expect("ingest");
        let facts = block_on(provider.enumerate()).expect("enumerate");
        assert_eq!(facts[0].link_class, LinkClass::Tunnel);
        assert!(!facts[0].is_overlay, "no overlay has been recorded");
    }

    #[test]
    fn a_dropped_event_is_itself_recorded_and_arrives_before_the_survivors() {
        let provider = AndroidInterfaceProvider::new(ShutdownLatch::new());
        let mut stream = provider.subscribe().expect("subscribe");

        // Overflow the queue by alternating the power posture, which is one
        // change per call and needs no new network.
        for i in 0..(SUBSCRIBER_QUEUE_DEPTH + 10) {
            provider.set_power(i % 2 == 0, false).expect("posture");
        }

        let first = poll_once(&mut stream).expect("something arrived");
        let NetworkChange::EventsLost { count } = first else {
            panic!("the gap must be reported first, got {first:?}");
        };
        assert_eq!(count, Some(10));
        // And the survivors follow.
        assert!(matches!(
            poll_once(&mut stream),
            Some(NetworkChange::LinkPostureChanged { .. })
        ));
    }

    #[test]
    fn several_subscribers_each_see_every_change() {
        let provider = AndroidInterfaceProvider::new(ShutdownLatch::new());
        let mut a = provider.subscribe().expect("a");
        let mut b = provider.subscribe().expect("b");
        provider.ingest(net(1, TransportSet::WIFI)).expect("ingest");
        assert!(poll_once(&mut a).is_some());
        assert!(poll_once(&mut b).is_some());
    }

    #[test]
    fn a_dropped_subscriber_is_pruned_rather_than_growing_a_queue_forever() {
        let provider = AndroidInterfaceProvider::new(ShutdownLatch::new());
        {
            let _stream = provider.subscribe().expect("subscribe");
        }
        provider.ingest(net(1, TransportSet::WIFI)).expect("ingest");
        assert_eq!(
            provider.inner.subscribers.lock().expect("lock").len(),
            0,
            "the closed subscriber is pruned on the next publish"
        );
    }

    #[test]
    fn subscribing_is_refused_after_shutdown_begins() {
        let latch = ShutdownLatch::new();
        let provider = AndroidInterfaceProvider::new(latch.clone());
        latch.begin();
        let Err(err) = provider.subscribe() else {
            panic!("subscribe must be refused once the latch is set");
        };
        assert!(matches!(err, PlatformError::ShuttingDown));
        assert!(matches!(
            block_on(provider.enumerate()).expect_err("latched"),
            PlatformError::ShuttingDown
        ));
    }

    #[test]
    fn a_change_arriving_during_shutdown_is_still_recorded() {
        // The snapshot is what the NEXT process reads at rehydration. Refusing
        // to record a real network change because we are exiting would leave it
        // describing a network the device has left.
        let latch = ShutdownLatch::new();
        let provider = AndroidInterfaceProvider::new(latch.clone());
        latch.begin();
        provider
            .ingest(net(1, TransportSet::WIFI))
            .expect("recorded");
        assert_eq!(provider.snapshot().expect("snapshot").networks().len(), 1);
    }

    #[test]
    fn an_ingest_that_changes_nothing_publishes_nothing() {
        let provider = AndroidInterfaceProvider::new(ShutdownLatch::new());
        provider.ingest(net(1, TransportSet::WIFI)).expect("first");
        let mut stream = provider.subscribe().expect("subscribe");
        provider
            .ingest(net(1, TransportSet::WIFI))
            .expect("same again");
        assert_eq!(poll_once(&mut stream), None);
    }
}
